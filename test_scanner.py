import subprocess
import random
from pathlib import Path
import templates

templates = ["sql_injection.py", "broken_access.py", "software_supply_chain.py"]

escolha = random.choice(templates)
codigo = Path(f"templates/{escolha}").read_text()

resultado = subprocess.run(
    ["semgrep", "scan", "--config", "p/python", f"templates/{escolha}"],
    capture_output=True,
    text=True,
    check=False)

print(resultado.stdout)


