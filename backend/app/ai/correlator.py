"""
Adaptado do detector.py do SecuraPy (Maick)
gerar_resumo_ameacas() adaptada para agrupar findings por arquivo.
defaultdict e lógica de pontuação copiados diretamente.
"""

from collections import defaultdict
from app.ai.scorer import classificar_severidade, calculate_pride_score


def agrupar_por_arquivo(findings: list) -> dict:
    """
    Equivalente ao detectar_brute_force() do SecuraPy.
    Em vez de contar FAILs por IP, conta findings por arquivo.
    Usa defaultdict igual ao detector.py.
    """
    # defaultdict copiado direto do detector.py
    contagem = defaultdict(lambda: {
        "total": 0,
        "criticos": 0,
        "score_max": 0.0,
        "regras": []
    })

    for f in findings:
        arquivo = f.get("file_path", "desconhecido")
        score   = f.get("pride_score", 0.0)
        contagem[arquivo]["total"]    += 1
        contagem[arquivo]["score_max"] = max(contagem[arquivo]["score_max"], score)
        contagem[arquivo]["regras"].append(f.get("rule_id", ""))
        if score >= 9.0:
            contagem[arquivo]["criticos"] += 1

    return dict(contagem)


def gerar_resumo_findings(findings: list) -> list:
    """
    Adaptado diretamente do gerar_resumo_ameacas() do SecuraPy.
    Em vez de consolidar IPs, consolida arquivos com vulnerabilidades.

    Mesma lógica de:
    - agrupar detecções
    - calcular pontuação combinada
    - ordenar do mais grave para o menos
    """
    # Mesmo MAPA_SEVERIDADE do detector.py
    MAPA_SEVERIDADE = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1, "INFO": 0}
    MAPA_INVERSO    = {v: k for k, v in MAPA_SEVERIDADE.items()}

    por_arquivo = agrupar_por_arquivo(findings)
    resumo = []

    for arquivo, dados in por_arquivo.items():
        score   = dados["score_max"]
        nivel   = classificar_severidade(score)
        pontos  = MAPA_SEVERIDADE.get(nivel, 0)

        # Bônus por múltiplos problemas no mesmo arquivo
        # Igual à lógica de múltiplas detecções do gerar_resumo_ameacas
        if dados["total"] >= 5:
            pontos = min(pontos + 1, 4)

        resumo.append({
            "arquivo":    arquivo,
            "total":      dados["total"],
            "criticos":   dados["criticos"],
            "score_max":  score,
            "severidade": MAPA_INVERSO[pontos],
            "pontuacao":  pontos,
            "regras":     list(set(dados["regras"]))
        })

    # Mesma ordenação do detector.py
    resumo.sort(key=lambda x: x["pontuacao"], reverse=True)
    return resumo