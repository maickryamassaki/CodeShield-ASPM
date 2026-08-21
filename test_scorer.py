# testa o PRIDE ScoreVerifica se a fórmula da Amanda está calculando corretamente os casos extremos.
from app.ai.scorer import calculate_pride_score

def test_critical_injcao_score_maximo():
    score = calculate_pride_score("CRITICAL")
    assert score == 10.0

def test_low_generico_score_baixo():
    score = calculate_pride_score("LOW")
    assert score <= 3.0

def test_score_nunca_passa_de_10():
    score = calculate_pride_score("CRITICAL", "injection.xss.auth",
                                   epss=1.0, cisa_kev=True)
    assert score <= 10.0

def test_cisa_kev_aumenta_score():
    sem_kev = calculate_pride_score("HIGH", "generic", cisa_kev=False)
    com_kev = calculate_pride_score("HIGH", "generic", cisa_kev=True)
    assert com_kev > sem_kev

