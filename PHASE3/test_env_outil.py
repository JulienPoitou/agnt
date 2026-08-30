#!/usr/bin/env python3
"""L'environnement remis à un outil est une liste blanche — et une liste blanche utile.

Deux moitiés, et la seconde compte autant que la première :

  · SÉCURITÉ — ce qui n'est pas listé n'existe pas pour l'outil. Constat G7 de la campagne
    adverse : `Sandbox.exec` faisait `dict(os.environ)` et emportait GH_TOKEN, GITHUB_TOKEN
    et la clé du fournisseur LLM dans le process qui parse le dépôt d'un attaquant.
  · FONCTIONNALITÉ — ce qui est listé arrive réellement, sinon le correctif n'est pas une
    correction mais un outil cassé. Un « 0 finding » produit par un semgrep qui ne trouve
    pas node vaut exactement ce que vaut un mensonge.

La fonction est testée directe, sans sandbox ni bwrap : `hote=` permet de poser un
environnement connu, ce qu'aucune assertion sur `exec` permettait de faire sur une machine
sans les binaires d'outils.

Usage : python3 PHASE3/test_env_outil.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "slice"))

import sandbox as S                                            # noqa: E402

CAS: list[tuple[str, bool, str]] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, cond, detail))


SECRETES = ("GH_TOKEN", "GITHUB_TOKEN", "GROQ_API_KEY", "AWS_SECRET_ACCESS_KEY",
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "npm_token", "DB_PASSWORD")

hote = {**{k: f"valeur-{k}" for k in SECRETES},
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "Europe/Paris",
        "HOME": "/home/qqn", "SHELL": "/bin/zsh", "SSH_AUTH_SOCK": "/tmp/x",
        "GIT_CONFIG_GLOBAL": "/home/qqn/.gitconfig-hote"}

e = S.environ_outil(hote=hote, montages={"HOME": "/tmp", "TMPDIR": "/tmp",
                                         "GIT_CONFIG_GLOBAL": "/mnt/gitcfg",
                                         "HTTP_PROXY": "http://127.0.0.1:9",
                                         "NO_PROXY": ""})

fuites = [k for k in SECRETES if k in e or any(v in e.values() for v in (hote[k],))]
cas("1. aucune variable à secret de l'hôte ne passe", not fuites, f"fuient : {fuites}")

cas("2. la valeur du fournisseur LLM n'est pas dans les valeurs non plus",
    not any("GROQ" in v or "valeur-GROQ" in v for v in e.values()), str(sorted(e))[:90])

cas("3. HOME de l'hôte n'est pas hérité — c'est le montage qui gagne",
    e.get("HOME") == "/tmp", f"obtenu : {e.get('HOME')!r}")

cas("4. le gitconfig de l'hôte n'est pas hérité non plus",
    e.get("GIT_CONFIG_GLOBAL") == "/mnt/gitcfg", f"obtenu : {e.get('GIT_CONFIG_GLOBAL')!r}")

cas("5. PATH, LANG, TZ arrivent (sinon l'outil tombe et le 0 est faux)",
    (e.get("PATH"), e.get("LANG"), e.get("TZ")) == ("/usr/bin:/bin", "C.UTF-8", "Europe/Paris"),
    str({k: v for k, v in e.items() if k in ('PATH', 'LANG', 'TZ')})[:90])

cas("6. le proxy mort est posé (double ceinture du --unshare-net)",
    e.get("HTTP_PROXY") == "http://127.0.0.1:9" and e.get("NO_PROXY") == "", str(e)[:80])

declare = {"GRYPE_DB_CACHE_DIR": "/mnt/db/grype", "PATH": "/opt/bin"}
d = S.environ_outil(declare=declare, hote=hote, montages={"HOME": "/tmp"})
cas("7. ce que le cœur déclaré passe, et passe EN DERNIER (comportement historique)",
    d.get("GRYPE_DB_CACHE_DIR") == "/mnt/db/grype" and d.get("PATH") == "/opt/bin",
    str(d)[:80])

# La liste blanche est un contrat : elle doit être courte et nommée, pas un filtre.
# Le mécanisme, pas l'énumération : une liste de secrets à exclure se contourne en
# inventant un nom de variable. On vérifie donc qu'aucun nom interdit n'y figure — le
# filtre serait invisible dans la liste, la liste blanche s'y lit.
cas("8. le mécanisme est une liste blanche, pas une liste noire de secrets",
    any(n.endswith("_AUTORISES") for n in dir(S))
    and not any(m in " ".join(S.ENV_HOTE_AUTORISES).upper()
                for m in ("TOKEN", "SECRET", "KEY", "PASSWORD")),
    str(S.ENV_HOTE_AUTORISES))

cas("9. exec() n'hérite plus de l'environnement complet",
    "dict(os.environ)" not in (Path(__file__).resolve().parent / "slice/sandbox.py")
    .read_text(encoding="utf-8").split("def exec", 1)[1].split("\n    def ", 1)[0],
    "encore un dict(os.environ) dans le corps de exec")

print()
for nom, cond, detail in CAS:
    print(("OK    " if cond else "ÉCHEC ") + nom + (f" — {detail}" if detail and not cond else ""))
n_ok = sum(1 for _, c, _ in CAS if c)
print(f"\n{n_ok}/{len(CAS)} cas vérifiés")
sys.exit(0 if n_ok == len(CAS) else 1)
