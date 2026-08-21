PESOS_SEVERIDADE = {
    "CRITICAL": 10.0,
    "HIGH":     8.0,
    "MEDIUM":   5.0,
    "LOW":      2.0,
    "INFO":     1.0,
    "WARNING":  3.0,
}

KEYWORDS_CRITICAS = [
    "injection", "sqli", "xss",
    "auth", "secret", "password", "token", "crypto",
]


def classificar_severidade(pontuacao: float) -> str:
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    else:
        return "INFO"


def calculate_pride_score(
    severity: str,
    rule_id: str,
    epss: float = 0.0,
    cisa_kev: bool = False,
) -> float:
    base = PESOS_SEVERIDADE.get(severity.upper(), 1.0)

    bonus_tipo = 1.5 if any(
        k in rule_id.lower() for k in KEYWORDS_CRITICAS
    ) else 0.0

    bonus_epss = round(epss * 2, 1)

    bonus_kev = 2.0 if cisa_kev else 0.0

    score = base + bonus_tipo + bonus_epss + bonus_kev
    return min(round(score, 1), 10.0)


if __name__ == "__main__":
    print(calculate_pride_score("CRITICAL", "python.injection.sqli"))
    print(calculate_pride_score("LOW", "generic.rule"))
    print(classificar_severidade(9.5))
    print(classificar_severidade(3.0))