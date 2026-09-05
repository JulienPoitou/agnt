"""Parser crlfuzz — lignes [VLN] du stdout, marqueur lu dans le SOURCE épinglé.

crlfuzz v1.4.1 (internal/runner/runner.go du tarball épinglé, lu) imprime pour
chaque URL vulnérable :

    if v {
        if options.Silent { fmt.Println(url) } else {
            fmt.Printf("[%s] %s\n", aurora.Green("VLN").String(), aurora.Green(url).String())
        } … }

soit une ligne « [VLN] <url> » par injection confirmée, en vert (ANSI retiré
par ce parser) — et RIEN sinon, que la cible soit propre ou injoignable
(mesuré : code 0 dans les deux cas). L'outil ne déclare ni sévérité ni CWE —
absents, jamais inventés ; le constat porte le CWE-93 (classification CRLF),
comme dotdotpwn porte le sien, et rien de plus.
"""
from __future__ import annotations

import re

from parsers import enregistrer

ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_]|[()][0-9A-B])")
RE_VLN = re.compile(r"^\[VLN\]\s*(\S+)\s*$")


@enregistrer("crlfuzz")
def parser_crlfuzz(stdout: str) -> list[dict]:
    items: list[dict] = []
    for brut in (stdout or "").splitlines():
        m = RE_VLN.match(ANSI.sub("", brut).strip())
        if m:
            items.append({
                "regle": "crlf-injection",
                "nom_regle": "CRLF injection",
                "message": "payload CRLF accepté — URL marquée [VLN] par crlfuzz",
                "url": m.group(1),
                "confiance": "confirmée",
                "cwe": "CWE-93",
            })
    return items
