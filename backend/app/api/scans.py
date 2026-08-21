"""
Módulo de rotas da CodeShield ASPM
Desenvolvido por: Maick
"""

from fastapi import APIRouter
from pydantic import BaseModel
from app.database import SessionLocal
from app.models import Finding
from app.scanners.semgrep import run_semgrep, normalizar_todos_findings
import subprocess, tempfile, shutil, os

router = APIRouter()


def extrair_trecho_codigo(repo_path: str, file_path: str, line: int, contexto: int = 3) -> str:
    """
    Lê o arquivo vulnerável e extrai algumas linhas ao redor
    do problema, para dar mais contexto à IA da Amanda.
    """
    try:
        caminho_completo = os.path.join(repo_path, file_path)
        with open(caminho_completo, "r", encoding="utf-8", errors="ignore") as f:
            linhas = f.readlines()

        linha_idx = int(line) - 1
        inicio = max(0, linha_idx - contexto)
        fim = min(len(linhas), linha_idx + contexto + 1)

        return "".join(linhas[inicio:fim]).strip()

    except Exception as e:
        print(f"[AVISO] Não foi possível extrair trecho de código: {e}")
        return ""


def limpar_caminho_arquivo(file_path: str, tmp: str) -> str:
    """
    Remove o caminho absoluto da pasta temporária,
    deixando só o caminho relativo dentro do repositório.
    """
    try:
        caminho_limpo = file_path.replace(tmp, "")
        caminho_limpo = caminho_limpo.lstrip("\\/")
        caminho_limpo = caminho_limpo.replace("\\", "/")
        return caminho_limpo if caminho_limpo else file_path
    except Exception:
        return file_path


@router.post("/scan")
def scan_repo(repo_url: str):
    tmp = tempfile.mkdtemp()
    db = None
    try:
        # 1. clona o repositório
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, tmp],
            capture_output=True, text=True, timeout=120
        )
        if clone.returncode != 0:
            return {"erro": "Não foi possível clonar", "detalhe": clone.stderr}

        # 2. roda o Semgrep
        findings_raw = run_semgrep(tmp)
        print(f"[DEBUG] Semgrep retornou {len(findings_raw)} findings brutos")

        if not findings_raw:
            return {"repo": repo_url, "total": 0}

        # 3. normaliza os findings
        findings = normalizar_todos_findings(findings_raw, repo_url)
        print(f"[DEBUG] Após normalização: {len(findings)} findings válidos")

        if not findings:
            print("[ERRO] Todos os findings foram descartados na normalização!")
            return {"repo": repo_url, "total": 0, "aviso": "Normalização descartou todos os findings"}

        # 4. abre o banco
        db = SessionLocal()
        salvos = 0

        for i, f in enumerate(findings, start=1):
            # 5. tenta chamar o scorer da amanda
            try:
                from app.ai.scorer import calculate_pride_score
                score = calculate_pride_score(f["tipo"], f["rule_id"])
            except Exception as e:
                print(f"[AVISO] Scorer falhou no finding {i}: {e}")
                score = 0.0

            file_path_limpo = limpar_caminho_arquivo(f["file_path"], tmp)

            # 6. tenta chamar a IA da amanda (com o trecho de código real)
            ai_fix = None
            if score >= 4.0:
                try:
                    from app.ai.remediation import generate_fix

                    trecho = extrair_trecho_codigo(
                        tmp,
                        f["file_path"],
                        f["line"]
                    )

                    ai_fix = generate_fix(
                        rule_id=f["rule_id"],
                        severity=f["tipo"],
                        file_path=file_path_limpo,
                        message=f["message"],
                        code_snippet=trecho
                    )
                except Exception as e:
                    print(f"[AVISO] IA indisponível no finding {i}: {e}")
                    ai_fix = None

            # 7. cria o objeto e adiciona à sessão
            try:
                novo = Finding(
                    repo_url=f["repo_url"],
                    rule_id=f["rule_id"],
                    severity=f["tipo"],
                    file_path=file_path_limpo,
                    line=f["line"],
                    message=f["message"],
                    pride_score=score,
                    ai_fix=ai_fix
                )
                db.add(novo)
                salvos += 1
            except Exception as e:
                print(f"[ERRO] Falha ao criar Finding {i}: {e}")

        print(f"[DEBUG] {salvos} findings adicionados à sessão, fazendo commit...")

        try:
            db.commit()
            print(f"[DEBUG] Commit realizado com sucesso — {salvos} findings salvos")
        except Exception as e:
            db.rollback()
            print(f"[ERRO CRÍTICO] Commit falhou: {e}")
            return {"erro": f"Falha ao salvar no banco: {e}"}

        return {"repo": repo_url, "total": salvos}

    except subprocess.TimeoutExpired:
        return {"erro": "Clone demorou mais de 2 minutos"}
    except Exception as e:
        print(f"[ERRO CRÍTICO] Falha geral no scan: {e}")
        return {"erro": str(e)}
    finally:
        if db:
            db.close()
        shutil.rmtree(tmp, ignore_errors=True)


@router.get("/findings")
def list_findings(severity: str = None, repo_url: str = None):
    db    = SessionLocal()
    query = db.query(Finding)
    if severity:
        query = query.filter(Finding.severity == severity)
    if repo_url:
        query = query.filter(Finding.repo_url == repo_url)
    result = query.order_by(Finding.pride_score.desc()).all()
    db.close()
    return result


@router.get("/resumo")
def resumo():
    from collections import Counter
    db       = SessionLocal()
    findings = db.query(Finding).all()
    db.close()
    return {
        "total":          len(findings),
        "por_severidade": dict(Counter(f.severity for f in findings)),
        "criticos":       sum(1 for f in findings if f.pride_score >= 9),
        "altos":          sum(1 for f in findings if 7 <= f.pride_score < 9),
    }


@router.delete("/findings")
def limpar():
    db = SessionLocal()
    db.query(Finding).delete()
    db.commit()
    db.close()
    return {"mensagem": "Findings removidos"}


# ─────────────────────────────────────────
# Rota do chatbot — usada pelo frontend do Caique
# Faz a ponte segura com a Claude API, evitando
# o bloqueio de CORS que acontece ao chamar
# a Anthropic diretamente do navegador.
# ─────────────────────────────────────────

class PerguntaRequest(BaseModel):
    pergunta: str
    findings: list


@router.post("/chat")
def chat_findings(request: PerguntaRequest):
    try:
        from app.ai.remediation import client, MODEL
    except Exception as e:
        return {"resposta": f"IA indisponível: {e}"}

    contexto = "\n".join([
        f"- {f.get('severity')} | Score: {f.get('pride_score')} | Arquivo: {f.get('file_path')} | {f.get('message')}"
        for f in request.findings[:10]
    ])

    prompt = f"""Você é um assistente de segurança da plataforma CodeShield ASPM.

Findings encontrados no repositório:
{contexto}

Pergunta: {request.pergunta}

Responda em português, de forma curta e direta.
"""

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        for block in response.content:
            if block.type == "text":
                return {"resposta": block.text}
        return {"resposta": "Sem resposta disponível."}
    except Exception as e:
        print(f"[ERRO] Chat falhou: {e}")
        return {"resposta": f"Erro ao consultar a IA: {e}"}