import requests
from requests.exceptions import Timeout, ConnectionError, HTTPError, RequestException

cache_epss = {}
cisa_kev_set = set()


def carregar_cisa_kev() -> set:
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=10,
        )
        r.raise_for_status()
        dados = r.json()
        cves = {v["cveID"] for v in dados.get("vulnerabilities", [])}
        print(f"[OK] CISA KEV carregado: {len(cves)} CVEs exploradas ativamente.")
        return cves

    except Timeout:
        print("[ERRO] Timeout ao carregar CISA KEV.")
    except ConnectionError:
        print("[ERRO] Sem conexão para carregar CISA KEV.")
    except Exception as e:
        print(f"[ERRO] Falha ao carregar CISA KEV: {e}")

    return set()


def consultar_epss(cve_id: str) -> float:
    if cve_id in cache_epss:
        return cache_epss[cve_id]

    try:
        r = requests.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}",
            timeout=5,
        )

        if r.status_code == 429:
            print("[AVISO] Limite de requisições EPSS atingido.")
            return 0.0

        r.raise_for_status()
        data = r.json().get("data", [])
        score = float(data[0]["epss"]) if data else 0.0

        cache_epss[cve_id] = score
        return score

    except Timeout:
        return 0.0
    except ConnectionError:
        return 0.0
    except HTTPError as e:
        print(f"[ERRO] EPSS HTTP error: {e}")
        return 0.0
    except RequestException as e:
        print(f"[ERRO] EPSS: {e}")
        return 0.0


def enriquecer_finding(finding: dict, cisa_kev: set) -> dict:
    cve_id = finding.get("rule_id", "")
    epss = consultar_epss(cve_id) if cve_id.startswith("CVE") else 0.0
    kev = cve_id in cisa_kev

    return {
        **finding,
        "epss": epss,
        "cisa_kev": kev,
    }


if __name__ == "__main__":
    kev_set = carregar_cisa_kev()
    finding_teste = {"rule_id": "CVE-2021-44228", "file_path": "app/log.py"}
    print(enriquecer_finding(finding_teste, kev_set))