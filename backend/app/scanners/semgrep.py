"""
Adaptado do coletor.py do SecuraPy 
Em vez de parsear linhas de log, parseia o JSON do Semgrep.
A lógica de normalização é idêntica, só muda a fonte.
"""

import subprocess
import json
import os
import shutil

# Caminho completo do executável do Semgrep
# Necessário porque o "semgrep" e o "python -m semgrep"
# não funcionam corretamente neste ambiente Windows
SEMGREP_EXE = r"C:\Users\maick\AppData\Local\Python\pythoncore-3.14-64\Scripts\semgrep.exe"

# Se o caminho fixo não existir, tenta achar no PATH do sistema
if not os.path.exists(SEMGREP_EXE):
    SEMGREP_EXE = shutil.which("semgrep") or "semgrep"


def normalizar_severidade(sev_raw: str) -> str:
    """
    O Semgrep retorna ERROR/WARNING/INFO.
    O scorer.py da Amanda espera CRITICAL/HIGH/MEDIUM/LOW.
    Sem esse mapeamento, tudo cai no fallback de score baixo.
    """
    mapeamento = {
        "ERROR":   "HIGH",
        "WARNING": "MEDIUM",
        "INFO":    "LOW"
    }
    return mapeamento.get(sev_raw.upper(), "LOW")


def run_semgrep(repo_path: str) -> list:
    """
    Em vez de abrir um arquivo .log, chama o Semgrep e captura o output.
    """

    # Verifica se o Semgrep está instalado
    try:
        subprocess.run(
            [SEMGREP_EXE, "--version"],
            capture_output=True, timeout=10
        )
    except FileNotFoundError:
        print("[ERRO] Semgrep não encontrado. Rode: pip install semgrep")
        return []

    try:
        resultado = subprocess.run(
            [
                SEMGREP_EXE,
                "--config", "auto",
                "--json",
                "--quiet",
                "--timeout", "60",
                repo_path
            ],
            capture_output=True,
            text=True,
            timeout=300
        )

        if not resultado.stdout.strip():
            print("[INFO] Semgrep não retornou findings.")
            print(f"[DEBUG] stderr: {resultado.stderr[:500]}")
            return []

        dados = json.loads(resultado.stdout)
        findings = dados.get("results", [])
        print(f"[OK] {len(findings)} vulnerabilidade(s) encontrada(s).")
        return findings

    except subprocess.TimeoutExpired:
        print("[ERRO] Semgrep demorou mais de 5 minutos.")
        return []
    except json.JSONDecodeError as erro:
        print(f"[ERRO] JSON inválido retornado pelo Semgrep: {erro}")
        return []
    except Exception as erro:
        print(f"[ERRO] Falha no Semgrep: {erro}")
        return []


def normalizar_finding(finding_raw: dict, repo_url: str) -> dict:
    """
    Transforma o formato bruto do Semgrep no formato padrão da CodeShield.
    """
    try:
        extra = finding_raw.get("extra", {})
        severity_raw = extra.get("severity", "INFO")
        severity = normalizar_severidade(severity_raw)
        rule_id = finding_raw.get("check_id", "")

        if not rule_id:
            return None

        return {
            "fonte":     "semgrep",
            "tipo":      severity,
            "repo_url":  repo_url,
            "rule_id":   rule_id,
            "file_path": finding_raw.get("path", ""),
            "line":      finding_raw.get("start", {}).get("line", 0),
            "message":   extra.get("message", ""),
            "detalhes":  f"rule={rule_id} file={finding_raw.get('path','')}",
        }
    except Exception:
        return None


def normalizar_todos_findings(findings_raw: list, repo_url: str) -> list:
    """
    Normaliza todos os findings de uma vez e ignora os inválidos.
    """
    normalizados = []
    for i, f in enumerate(findings_raw, start=1):
        resultado = normalizar_finding(f, repo_url)
        if resultado:
            normalizados.append(resultado)
        else:
            print(f"[AVISO] Finding {i} com formato inválido — ignorado.")
    return normalizados