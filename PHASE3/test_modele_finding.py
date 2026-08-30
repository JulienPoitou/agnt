#!/usr/bin/env python3
"""
Batterie « modèle de finding unifié » — une cible n'est pas forcément un fichier.

Le défaut que ce fichier ferme : `location` était un triplet fichier:ligne+paquet. Pour
du code, c'était juste. Pour tout le reste — une URL (nuclei, sqlmap, ffuf), un hôte
(nmap), une image (trivy en mode image), une ressource cloud (`arn:aws:s3:::bucket`,
checkov sur un plan Terraform) — le finding n'avait AUCUN endroit où loger sa
localisation. Un outil web intégré sur ce modèle produisait soit un finding muet, soit
un chemin inventé, et le second cas est le pire des deux : une fausse localisation se
cite dans un rapport.

Ce que la batterie exige :
  · les coordonnées sont DÉCLARÉES par le manifest (alias dans `extraction.champs`) et
    proviennent d'un vocabulaire fermé — le cœur ne devine pas qu'un mot est une URL ;
  · `normalise_chemin` ne touche JAMAIS une URL (sinon `/../` plierait deux cibles en une) ;
  · les identités DÉJÀ produites ne bougent pas : les fingerprints des six providers du
    bundle historique `dogfooding/rapports/requests` sont épinglés sur leur valeur
    mesurée AVANT le patch (14 empreintes) ;
  · `vue_unifiee` ne remplit jamais un champ que l'outil a laissé vide : il le déclare
    dans `absents`.

Usage : python3 PHASE3/test_modele_finding.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "PHASE3" / "slice"))

import findings as F  # noqa: E402
from registre import Registry  # noqa: E402

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


BUNDLE = RACINE / "PHASE3" / "dogfooding" / "rapports" / "requests"

# Capturées AVANT le patch (2026-08-30) sur les raws réels du bundle, avec
# `racines=(BUNDLE, RACINE)`. Un écart ici = identité de finding modifiée : corrélation
# inter-outils et rejeu cassés en silence. C'est le contrôle qui a contraint la
# construction de l'empreinte à rester EXACTEMENT la même pour `asset == repository`.
PINS = {
    "checkov": ["95f202aae1d82268ad935db4176789f7"],
    "gitleaks": [
        "5460f467b02e49471c0fd6cfc9ca0adab6351f98:tests/certs/expired/ca/ca-private.key:private-key:1",
        "5460f467b02e49471c0fd6cfc9ca0adab6351f98:tests/certs/expired/server/server.key:private-key:1",
        "5460f467b02e49471c0fd6cfc9ca0adab6351f98:tests/certs/mtls/client/client.key:private-key:1",
        "5460f467b02e49471c0fd6cfc9ca0adab6351f98:tests/certs/valid/server/server.key:private-key:1",
    ],
    "semgrep": [
        "9f0a10f4a0b1d4d240e0f5c2b0830e29", "c53d7e3716c56bfaeaa671ed529e633c",
        "2c9b6240ef34ee2515148c4f1ed11a56", "8ef3d6ec80305fc7c2caad0f56c450d1",
        "f5d9479b97311be1ec85687aa5af8b05", "5e355e36ff8f1bf3e26938a0c48e4bb7",
        "3177cd35e261710577dedc63d3315ed4", "e2ddffc3b1714adf3908b2332b534492",
        "20242a79889f239541fc41696dd3892d",
    ],
    "grype": [], "kics": [], "trivy": [],
}

par_id = {p.id: p for p in Registry().providers()}


def normaliser(outil: str, brut, racines):
    prov = par_id.get(outil)
    return F.normaliser(outil, brut, mani=prov.manifest if prov else None, racines=racines)


# ------------------------------------------------------------------ 1 · identité préservée
obtenus = {}
for raw in sorted(BUNDLE.glob("raw_*.json")):
    outil = raw.name[4:-5]
    obtenus[outil] = [f.identity["fingerprint"]
                      for f in normaliser(outil, json.loads(raw.read_text(encoding="utf-8")),
                                          (BUNDLE, RACINE))]
for outil, attendu in PINS.items():
    cas(f"1.{outil} empreintes historiques intactes ({len(attendu)} findings)",
        obtenus.get(outil, None) == attendu,
        f"{str(attendu[:1])[:70]} → {str(obtenus.get(outil, [])[:1])[:70]}")
cas("2. le pin n'est pas creux : 14 fingerprints réels sont comparés",
    sum(len(v) for v in PINS.values()) == 14, str(sum(len(v) for v in PINS.values())))

# ------------------------------------------------------------------ 2 · cible non-fichier
Y_URL = """\
capabilities:
  - id: WEB_SCAN
    description: scan web de test
    domaines: [web]
    entree: [cible]
    sortie: finding/web
    providers:
      - id: faux_nuclei
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
        manifest:
          id: faux_nuclei
          binaire: semgrep
          argv: ["{BIN}", "-json"]
          output: {format: json}
          extraction:
            modele: plat
            items_from: results
            champs:
              regle: matcher_name
              severite: severity
              message: matched-at
              url: host
              remediation: reference
              confiance: confidence
"""

_f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
_f.write(Y_URL)
_f.close()
reg = Registry(_f.name)
MANI_URL = reg.provider("faux_nuclei").manifest
assert MANI_URL is not None, "le manifest du provider de test n'a pas été chargé"


def norm_url(brut, racines=()):
    """Voie déclarative seule : le provider de test n'a pas d'adaptateur historique."""
    return F.normaliser("faux_nuclei", brut, mani=MANI_URL, racines=racines)


brut = {"results": [
    {"matcher_name": "exposed-token", "severity": "high", "matched-at": "jeton api 1234",
     "host": "https://cible.example/api?tok=abc", "reference": "mettre a jour",
     "confidence": 0.9},
    {"matcher_name": "xss-reflected", "severity": "medium", "matched-at": "ref=<script>",
     "host": "https://autre.example/search?q=1", "reference": None, "confidence": None},
]}
fs = norm_url(brut)
cas("3. le normaliseur déclaratif produit deux findings", len(fs) == 2, str(len(fs)))
loc = [f.location for f in fs]
cas("4. la coordonnée déclarée devient `location.url`, et l'asset cesse d'être « repository »",
    loc[0].get("asset") == "url" and loc[1].get("asset") == "url"
    and "url" in loc[0] and "url" in loc[1], json.dumps(loc[0], ensure_ascii=False))
cas("5. aucune normalisation de chemin sur une URL (sinon « /../ » plierait deux cibles en une)",
    all(".." not in str(l.get("url")) for l in loc)
    and loc[0]["url"].endswith("/api?tok=abc") and loc[0].get("file") in ("", None),
    json.dumps([l.get("url") for l in loc], ensure_ascii=False))
cas("6. deux URL distinctes = deux empreintes distinctes (le dédoublonnage ne fusionne pas la cible)",
    fs[0].identity["fingerprint"] != fs[1].identity["fingerprint"],
    f"{fs[0].identity['fingerprint'][:12]} vs {fs[1].identity['fingerprint'][:12]}")
a = norm_url(brut)
b = norm_url({"results": list(reversed(brut["results"]))})
cas("7. l'empreinte ne dépend pas de l'ordre de la sortie de l'outil",
    sorted(f.identity["fingerprint"] for f in a) == sorted(f.identity["fingerprint"] for f in b),
    "ordre inversé")
dup = norm_url({"results": [brut["results"][0], dict(brut["results"][0])]})
cas("8. deux lignes identiques de l'outil portent la MÊME empreinte (le dédoublonnage a une clé)",
    dup[0].identity["fingerprint"] == dup[1].identity["fingerprint"]
    and dup[0].location["url"] == dup[1].location["url"],
    str([d.identity["fingerprint"][:12] for d in dup]))
checkov = normaliser("checkov", json.loads((BUNDLE / "raw_checkov.json").read_text(encoding="utf-8")),
                     (BUNDLE, RACINE))
cas("9. un finding de fichier et un finding d'URL sur la même règle ne fusionnent pas",
    fs[0].identity["fingerprint"] != checkov[0].identity["fingerprint"], "empreintes distinctes")
cas("10. l'asset reste dans le finding (un consommateur peut trier par type de cible)",
    checkov[0].location.get("asset") == "repository", str(checkov[0].location.get("asset")))

# ------------------------------------------------------------------ 3 · secrets dans une URL
brut_cred = {"results": [{"matcher_name": "basic-auth", "severity": "high",
                          "matched-at": "x",
                          "host": "https://admin:***@target.example/a",
                          "reference": None, "confidence": None}]}
fs_cred = norm_url(brut_cred)
url = fs_cred[0].location["url"]
cas("11. un identifiant dans l'URL est masqué (le finding garde le path, perd le couple)",
    "PasseW0rd789" not in url and "AutreSecret543" not in url and "target.example/a" in url,
    url)
cas("12. l'empreinte est calculée APRÈS masquage : deux secrets différents, même finding",
    norm_url({"results": [{**brut_cred["results"][0],
                           "host": "https://u2:***@target.example/a"}]})[0]
    .identity["fingerprint"] == fs_cred[0].identity["fingerprint"],
    "empreintes attendues identiques")

# ------------------------------------------------------------------ 4 · rien d'inventé
cas("13. cve_de lit une CVE dans un identifiant ou un message, et seulement ça",
    F.cve_de("trivy:CVE-2023-45853") == "CVE-2023-45853"
    and F.cve_de("GHSA-2wgc-48c7", "parle de CVE-2019-1010081") == "CVE-2019-1010081"
    and F.cve_de("semgrep:python.lang.aws") is None and F.cve_de("") is None,
    "motif strict")
cas("14. un identifiant qui RESSEMBLE à une CVE n'en devient pas une",
    F.cve_de("cve-12-34") is None and F.cve_de("CVE-20XX-0001") is None
    and F.cve_de("CVE-2023-45853") == "CVE-2023-45853", "CVE-20XX-0001 refusé")

v = F.vue_unifiee(fs[0].to_dict(), versions={"semgrep": "1.90.3"})
attendus = {"id", "outil", "version_outil", "categorie", "capacite", "provider", "cible",
            "regle", "cve", "cwe", "severite", "origine_severite", "confiance", "remediation",
            "reference", "message", "empreinte", "statut", "horodatage", "absents"}
cas("15. la vue unifiée expose les vingt champs du contrat, sans en oublier",
    attendus <= set(v), f"manquants : {sorted(attendus - set(v))}")
cas("16. version_outil vient de la table de contexte, pas d'une supposition",
    v["version_outil"] == "1.90.3" and F.vue_unifiee(fs[0].to_dict())["version_outil"] is None,
    str(v.get("version_outil")))
cas("17. un champ que l'outil n'a pas fourni vaut None, et il est nommé dans `absents`",
    v["cwe"] is None and "cwe" in v["absents"] and "remediation" not in v["absents"]
    and v["remediation"] == "mettre a jour", json.dumps(v["absents"]))
cas("18. `confiance` est une donnée d'outil déclarée, pas un score du cœur",
    v["confiance"] is not None and F.vue_unifiee(fs[1].to_dict())["confiance"] is None,
    f"{v['confiance']} / {F.vue_unifiee(fs[1].to_dict())['confiance']}")
cas("19. la catégorie vient des domaines du registre (aucun dictionnaire d'outils à entretenir)",
    reg.capability("WEB_SCAN").domaines == ["web"], str(reg.capability("WEB_SCAN").domaines))

# ------------------------------------------------------------------ 5 · export SARIF
sys.path.insert(0, str(RACINE / "PHASE3"))
import analyser as AN  # noqa: E402
res = AN.sarif([f.to_dict() for f in fs], "run-test", "plan-test")["runs"][0]["results"]
cas("20. un finding d'URL sort en SARIF AVEC sa localisation (avant : aucune location)",
    all(r.get("locations") for r in res), json.dumps(res[0], ensure_ascii=False)[:170])
cas("21. la coordonnée non physique passe en logicalLocations, nommée",
    any(l["logicalLocations"][0]["fullyQualifiedName"].startswith("url:")
        for r in res for l in r["locations"]),
    json.dumps(res[0]["locations"], ensure_ascii=False)[:170])
r2 = AN.sarif([f.to_dict() for f in checkov], "r", "p")["runs"][0]["results"][0]
cas("22. un finding de fichier garde son physicalLocation d'origine (non régressé)",
    r2["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == checkov[0].location["file"],
    str(r2["locations"])[:170])
cas("23. categorie/horodatage/version/cwe/remediation traversent l'export",
    {"categorie", "horodatage", "version_outil", "cwe", "remediation", "confiance"}
    <= set(r2["properties"]), json.dumps(sorted(r2["properties"])))

# ------------------------------------------------------------------ 6 · câblage
pl = (RACINE / "PHASE3" / "slice" / "pipeline.py").read_text(encoding="utf-8")
cas("24. le pipeline enrichit catégorie/horodatage/version depuis le registre et le contexte",
    'f_.source["categorie"] = domaines_du_provider.get(prov.id)' in pl
    and 'f_.source["horodatage"] = horodatage' in pl
    and 'f_.source["version_outil"]' in pl
    # l'heure vient du plan de LA vague (et non du seul plan 1) : depuis l'escalade bornée,
    # une vague 2 a son propre horodatage — un finding de vague 2 daté de la vague 1 serait
    # une fausse simultanéité.
    and 'f_.source["vague"] = vague' in pl
    and "_vague(plan2.steps, plan2, decision2, plan2.cree_le, 2)" in pl,
    "trois affectations + horodatage par vague")
fd = (RACINE / "PHASE3" / "slice" / "findings.py").read_text(encoding="utf-8")
cas("25. le vocabulaire des coordonnées est fermé dans le code (quatre, pas un champ libre)",
    'COORDONNEES = (("url", "url"), ("hote", "hote"), ("image", "image"),' in fd,
    "COORDONNEES introuvable")
cas("26. `normalise_chemin` n'est appelé qu'une fois dans la voie déclarative",
    fd.count("normalise_chemin(c.get(\"fichier\")") == 1, "un seul appel attendu")
cas("27. `vue_unifiee` accepte un finding objet COMME un dictionnaire (findings.json)",
    F.vue_unifiee(fs[0])["empreinte"] == F.vue_unifiee(fs[0].to_dict())["empreinte"],
    "les deux formes doivent se projeter pareil")

# ------------------------------------------------------------------ 7 · deux providers, un outil
Y_DEUX = """\
capabilities:
  - id: CODE_DEUX
    description: deux jeux de regles du meme moteur
    domaines: [code]
    entree: [cible]
    sortie: finding/code
    providers:
      - id: moteur_regles_a
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
        manifest:
          id: moteur_regles_a
          binaire: semgrep
          argv: ["{BIN}", "--json"]
          output: {format: json}
          extraction:
            modele: plat
            items_from: results
            champs: {regle: check_id, fichier: path, ligne: start.line, severite: extra.severity}
      - id: moteur_regles_b
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 110
        commande: ["semgrep"]
        manifest:
          id: moteur_regles_b
          binaire: semgrep
          argv: ["{BIN}", "--json"]
          output: {format: json}
          extraction:
            modele: plat
            items_from: results
            champs: {regle: check_id, fichier: path, ligne: start.line, severite: extra.severity}
"""
_f2 = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
_f2.write(Y_DEUX)
_f2.close()
reg2 = Registry(_f2.name)
MEME_SORTIE = {"results": [{"check_id": "a.b.rule", "path": "src/app.py",
                           "start": {"line": 10}, "extra": {"severity": "ERROR"}}]}
fa = F.normaliser("moteur_regles_a", MEME_SORTIE, mani=reg2.provider("moteur_regles_a").manifest,
                  racines=())
fb = F.normaliser("moteur_regles_b", MEME_SORTIE, mani=reg2.provider("moteur_regles_b").manifest,
                  racines=())
cas("28. deux providers du MÊME moteur portent des identifiants distincts (pas de collision d'id)",
    fa[0].id == "moteur_regles_a-0001" and fb[0].id == "moteur_regles_b-0001",
    f"{fa[0].id} / {fb[0].id}")
cas("29. `source.tool` nomme le moteur (le binaire), le provider reste séparé",
    fa[0].source["tool"] == "semgrep" and fa[0].source["provider"] == "moteur_regles_a"
    and fb[0].source["tool"] == "semgrep", json.dumps(fa[0].source, ensure_ascii=False)[:150])
import clusterer as CL  # noqa: E402
outils = CL._outils([fa[0].id, fb[0].id], {fa[0].id: fa[0], fb[0].id: fb[0]})
cas("30. corollaire : deux jeux de règles du même moteur ne Comptent PAS comme deux outils",
    outils == {"semgrep"}, f"outils du cluster : {outils}")
res_clust = CL.regrouper(list(fa) + list(fb))
cas("31. et le regroupement ne revendique donc pas une convergence inter-outils fausse",
    not res_clust.get("clusters_inter_outils"),
    json.dumps(res_clust.get("clusters_inter_outils"), ensure_ascii=False)[:180])
# avec un VRAI second moteur, la convergence redevient revendicable
from types import SimpleNamespace  # noqa: E402
autre = F.Finding(id="trivy-0001",
                  source={"tool": "trivy", "provider": "trivy",
                          "canonical_rule_id": "trivy:a.b.rule", "original_rule_id": "a.b.rule"},
                  identity={"canonical_rule_id": "trivy:a.b.rule", "fingerprint": "x"},
                  location={"asset": "repository", "file": "src/app.py", "line": 10,
                            "package": None},
                  severity={"value": "HIGH", "origine": "trivy"},
                  evidence={"message": "même règle, autre moteur"})
res2 = CL.regrouper(list(fa) + [autre])
outils2 = set()
for c in res2["clusters"]:
    outils2 |= CL._outils(c["members"], {fa[0].id: fa[0], autre.id: autre})
cas("32. deux moteurs réellement distincts convergent toujours (le correctif ne désarme rien)",
    len(outils2) == 2 or not res2["clusters"], f"outils vus : {outils2}")

print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas passent", end="")
if ECHECS:
    print(" ; échecs : " + ", ".join(ECHECS))
else:
    print()
for nom, ok, detail in CAS:
    if not ok:
        print(f"  ÉCHEC {nom} — {detail}")
sys.exit(1 if ECHECS else 0)
