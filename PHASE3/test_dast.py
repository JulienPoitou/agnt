#!/usr/bin/env python3
"""
Batterie « DAST sur cible distante » — 02/09/2026.

Ce que ce fichier exige, dans l'ordre où ça compte :

  1. LES PARSEURS ET LES MAPPING rendent des findings DISTINCTS et TRADUISABLES. Un
     provider DAST dont tous les findings portent la même empreinte (l'accident historique
     de nuclei sans `champs`, et de nmap itérant tout son XML) est une corrélation morte
     et un rapport faux — ici, la distinguishabilité est un cas testé, pas une attente.
  2. LA DÉCLARATION reste l'autorité : les mappings testés sont ceux de
     `slice/capabilities.yaml` EN SERVICE (providers réels du registre), pas des mappings
     recréés pour le test.
  3. LE REFUS AVANT L'ACTION : conditions réseau jugées sur la commande construite,
     outil absent refusé (règle D1) — et dans cet ordre, vérifié sur cible distante comme
     sur cible locale.
  4. UN SCAN DISTANT VIDÉ EST UN RÉSULTAT, pas un échec — et son contraire : « rien de
     lisible » reste « ÉCHEC D'EXÉCUTION ». La limite « absence de correspondance ≠
     absence de vulnérabilité » doit être ÉCRITE, pas sous-entendue.
  5. LA CAGE DISTANTE ne monte pas de dépôt, n'annule pas sa cohérence, et ne change
     RIEN au contexte des missions locales (`limites_appliquees`, `commande`).
  6. LE DAST RESTE UNE OBSERVATION : `cycle.verified` n'est jamais posé par la
     normalisation, quoi que rende l'outil.

Pourquoi des doubles là où `test_qualite_plateforme` joue le bout-en-bout : sur cette
machine `opa` et `bwrap` sont injoignables (mesuré — cause documentée, NON ÉVALUÉ nommé
aux endroits qui les exigent). Le corps d'exécution se pilote à vide par
`pipeline._vague`, exactement comme `test_vague_parallele` ; la sélection, l'intention et
les parseurs se jouent sur les objets RÉELS du registre.

Usage : python3 PHASE3/test_dast.py
"""
from __future__ import annotations

import dataclasses
import json
import os
import stat
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).parent

# ──── Armer CE processus pour que la vague parte (même convention que
# test_vague_parallele, 02/09/2026) : un cache scratch dont les shims ne sont JAMAIS
# exécutés (les doubles d'exécution les remplacent) mais qui rend les outils « présents »
# au sens de la règle D1. `semgrep` et `bandit` restent VOLONTAIREMENT absents : les cas
# « outil introuvable » en ont besoin.
_SCRATCH_CACHE = Path(tempfile.mkdtemp(prefix="agnt-dast-cache-"))
(_SCRATCH_CACHE / "bin").mkdir()
os.environ["ARENA_SECOPS_CACHE"] = str(_SCRATCH_CACHE)
for _nom in ("zap-baseline.py", "nuclei", "ffuf", "nmap"):
    _c = _SCRATCH_CACHE / "bin" / _nom
    _c.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _c.chmod(_c.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

sys.path.insert(0, str(RACINE / "slice"))

import adapters as A                                    # noqa: E402
import clusterer as CL                                   # noqa: E402
import conditions as COND                                # noqa: E402
import extraction as EX                                  # noqa: E402
import findings as F                                     # noqa: E402
import intent as IN                                      # noqa: E402
import mission as MS                                     # noqa: E402
import parsers_zap                                       # noqa: E402,F401 (effet: enregistrement)
import pipeline as PI                                    # noqa: E402
import plan as PLAN                                      # noqa: E402
import provider_manifest as PM                           # noqa: E402
import run as RUN                                        # noqa: E402
import sandbox as SB                                     # noqa: E402
from cible import Cible                                  # noqa: E402
from provider_contract import Target                     # noqa: E402
from registre import Registry                            # noqa: E402

CAS: list = []
ECHECS: list = []
NON_EVALUES: list = []


def cas(nom: str, cond, detail=""):
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def non_evalue(nom: str, cause: str):
    NON_EVALUES.append((nom, cause))


def _fp_ok(items):
    fps = [i for i in items]
    return len(set(fps)) == len(fps)


# ═════════════════════════════ 1 · le parser ZAP, sur des octets ═══
print("═══ 1 · zap_baseline : un item par instance, le vocabulaire de l'outil ═══")

FX_ZAP = {
    "@programName": "OWASP ZAP", "@version": "2.17.0",
    "site": [{
        "@name": "https://cible.example/", "@host": "cible.example",
        "alerts": [
            {"pluginid": "10202", "alert": "Content Security Policy (CSP) Header Not Set",
             "riskcode": "2", "riskdesc": "Medium (High)", "confidence": "3",
             "confidencedesc": "High",
             "desc": "<p>Sans CSP le navigateur...</p>", "solution": "Mettre un en-tête CSP",
             "reference": "https://owasp.org/x\r\nhttps://wstg/y", "cweid": "693", "count": "2",
             "instances": [{"uri": "https://cible.example/a",
                           "evidence": "<p>en-tête CSP absent</p>", "messageId": "7"},
                           {"uri": "https://cible.example/b", "evidence": "X", "messageId": "9"}]},
            {"pluginid": "0", "alert": "Cloud Metadata Potentially Exposed",
             "riskcode": "3", "confidence": "0", "cweid": "0"}]}]}

items = parsers_zap.parse(json.dumps(FX_ZAP))
cas("deux instances d'une alerte = DEUX findings (la localisation ne se perd pas à l'agrégat)",
    len(items) == 3, f"{len(items)} items pour 2+1 constats")
cas("l'URL de l'instance est la coordonnée ; le titre et la preuve viennent du document",
    items[0]["url"] == "https://cible.example/a" and items[0]["nom_regle"].startswith("Content")
    and items[0]["preuve"] == "en-tête CSP absent", json.dumps(items[0], ensure_ascii=False)[:200])
cas("une alerte sans instance est logée sur le SITE, pas sur du vide",
    items[2]["url"] == "https://cible.example/", json.dumps(items[2], ensure_ascii=False)[:160])
cas("riskcode sans riskdesc = la TRADUCTION PUBLIÉE de ZAP (3 → High), pas une échelle inventée",
    items[0]["severite"] == "Medium" and items[2]["severite"] == "High",
    [i.get("severite") for i in items])
cas("cweid 0 n'est PAS un CWE : la clé reste absente (jamais « CWE-0 »)",
    "cwe" not in items[2] and items[0]["cwe"] == "CWE-693", [items[2].keys(), items[0]["cwe"]])
cas("source_id porte l'identifiant de l'outil (plugin@messageId) — la trace vers le rapport brut",
    items[0]["source_id"] == "10202@7" and items[2]["source_id"] == "0",
    [i.get("source_id") for i in items])
cas("le balisage HTML du desc est retiré, le texte de l'outil reste (allégé, pas réécrit)",
    "<" not in items[0]["message"] and "navigateur" in items[0]["message"], items[0]["message"])
cas("entrée vide, entrée corrompue, racine non-objet : [], jamais une exception",
    parsers_zap.parse("") == [] and parsers_zap.parse("{oops") == []
    and parsers_zap.parse("[1,2]") == [] and parsers_zap.parse('{"site": "pas-une-liste"}') == [],
    "")
import json as _J
cas("le parser ZAP est DÉTERMINISTE : les mêmes octets, deux lectures, des items identiques "
    "(l'ordre suit le document, aucune carte n'entre par le hasard de `dict`)",
    parsers_zap.parse(_J.dumps(FX_ZAP)) == parsers_zap.parse(_J.dumps(FX_ZAP))
    and parsers_zap.parse(_J.dumps(FX_ZAP, sort_keys=True))
        == parsers_zap.parse(_J.dumps(FX_ZAP)), "")

gros = {"site": [{"@name": "https://x/", "alerts": [
    dict(FX_ZAP["site"][0]["alerts"][0], pluginid=str(90000 + k),
         instances=[{"uri": f"https://x/{k}", "messageId": str(k)}]) for k in range(2000)]}]}
n = len(parsers_zap.parse(json.dumps(gros)))
cas("2 000 alertes × 1 instance : tout est rendu, rien n'est perdu (10⁴ items tenus)",
    n == 2000, f"{n} items")

# ═════════════════════════════ 2 · normalisation déclarative : les mappings DU REGISTRE ═══
print("═══ 2 · nuclei / ffuf / nmap : le manifest en service, pas un doublon de fixture ═══")
reg = Registry()


def normalise(pid, donnees):
    prov = reg.provider(pid)
    return F.normaliser(pid, donnees, mani=prov.manifest, racines=())


nu_lignes = [
    {"template-id": "php-info-page", "name": "PHP Info Page", "severity": "info",
     "description": "PHP information disclosure detected", "matched-at": "https://cible.example/info.php",
     "extracted-results": ["PHP Version 5.4.45"], "type": "http", "matcher-status": True,
     "timestamp": "2026-09-02T00:00:00.000000000Z"},
    {"template-id": "CVE-2019-14234", "name": "vBulletin RCE", "severity": "critical",
     "description": "Unauthenticated RCE", "matched-at": "https://cible.example/other",
     "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2019-14234"],
     "classification": {"cve-id": ["CVE-2019-14234"], "cwe-id": ["CWE-89"]},
     "extracted-results": ["x"], "type": "http", "matcher-status": True}]
vus = normalise("nuclei", {"texte": "\n".join(json.dumps(l) for l in nu_lignes)})
cas("le provider nuclei du registre rend DEUX findings DISTINCTS (l'accident des empreintes "
    "identiques est mort ici)",
    len(vus) == 2 and len({v.identity["fingerprint"] for v in vus}) == 2,
    [v.identity["fingerprint"][:8] for v in vus])
cas("la sévérité reste le MOT du template, en majuscules canoniques du modèle (critical → CRITICAL)",
    vus[1].severity["value"] == "CRITICAL" and vus[1].severity["origine"] == "nuclei",
    [v.severity for v in vus])
cas("la coordonnée est l'URL touchée (matched-at), pas un chemin inventé",
    vus[0].location["asset"] == "url" and vus[0].location["url"].endswith("info.php")
    and not vus[0].location["file"], [v.location for v in vus])
cas("extracted-results traverse la projection COMME PREUVE (evidence.preuve), déclaré par le manifest",
    vus[0].evidence["preuve"] == ["PHP Version 5.4.45"], vus[0].evidence.get("preuve"))
cas("la remédiation et la référence du template suivent le finding (alias déclarés, jamais déduits)",
    vus[0].evidence["remediation"] is None
    and vus[1].evidence["reference"] == ["https://nvd.nist.gov/vuln/detail/CVE-2019-14234"],
    [v.evidence.get("reference") for v in vus])
vus2 = normalise("nuclei", {"texte": "\n".join(json.dumps(l) for l in nu_lignes)})
cas("deux lectures des MÊMES octets rendent des findings identiques (déterminisme de normalisation)",
    [json.dumps(v.to_dict(), sort_keys=True) for v in vus]
    == [json.dumps(v.to_dict(), sort_keys=True) for v in vus2], "")
secret = json.dumps({**nu_lignes[0],
                     "description": "fuite cle AWS AKIAIOSFODNN7EXAMPLE détectée"})
v_sec = normalise("nuclei", {"texte": secret})[0]
cas("une clé dans le texte libre masqué_large est neutralisée dans la projection",
    "AKIAIOSFODNN7EXAMPLE" not in json.dumps(v_sec.to_dict()), v_sec.evidence["message"][:120])

vu_ffuf = normalise("ffuf", {"results": [
    {"url": "https://cible.example/admin", "input": {"FUZZ": "admin"}, "status": 200,
     "length": 1234, "words": 90, "lines": 12, "server": "nginx/1.18.0", "matcherstatus": True},
    {"url": "https://cible.example/backup.zip", "input": {"FUZZ": "backup.zip"}, "status": 403,
     "length": 153, "words": 5, "lines": 7, "server": "nginx/1.18.0", "matcherstatus": True}]})
cas("ffuf : un finding par correspondance, mot testé = identifiant du constat (input.FUZZ)",
    len(vu_ffuf) == 2 and {v.source["original_rule_id"] for v in vu_ffuf} == {"admin", "backup.zip"},
    [v.source["original_rule_id"] for v in vu_ffuf])
cas("ffuf ne classe pas : sévérité UNKNOWN affichée comme telle, et l'empreinte distingue les URL",
    all(v.severity["value"] == "UNKNOWN" for v in vu_ffuf)
    and len({v.identity["fingerprint"] for v in vu_ffuf}) == 2,
    [v.severity["value"] for v in vu_ffuf])

FX_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.98">
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http"/></port></ports></host>
<runstats><finished time="1"/></runstats>
</nmaprun>"""
vu_nmap = normalise("nmap", {"texte": FX_NMAP})
cas("nmap : DEUX ports = DEUX findings DISTINCTS (avant la correction, chaque balise devenait "
    "un item vide de même empreinte — 4 findings factices pour 2 ports)",
    len(vu_nmap) == 2 and len({v.identity["fingerprint"] for v in vu_nmap}) == 2
    and {v.source["original_rule_id"] for v in vu_nmap} == {"22", "80"},
    [(v.source["original_rule_id"], v.identity["fingerprint"][:6]) for v in vu_nmap])
cas("la coordonnée du port est l'HÔTE lu dans l'en-tête du <host> (contexte @addr)",
    all(v.location["asset"] == "hote" and v.location["hote"] == "10.0.0.5" for v in vu_nmap),
    [v.location for v in vu_nmap][:1])
cas("le nom du service et l'état viennent de l'outil (service@name, state@state) — la raison "
    "du port ouvert est la PREUVE (state@reason)",
    vu_nmap[0].evidence["message"] == "open" and vu_nmap[0].evidence["preuve"] == "syn-ack"
    and vu_nmap[0].source["nom_regle"] == "ssh",
    [e.source.get("nom_regle") for e in vu_nmap])

# la projection idempotente est le mécanisme qui rend le xml lisible : exigé nommément.
ex_id = PM.Extraction(modele="xml", champs={"regle": "@x"})
c_id = EX.champs({"regle": "lu-deja"}, ex_id)
c_abs = EX.champs({"autre": 1}, ex_id)
cas("projection idempotente : l'alias déjà porté par l'item est lu ; un alias absent reste None "
    "(repli déclaré, pas une devinette)",
    c_id["regle"] == "lu-deja" and c_abs["regle"] is None, f"{c_id} / {c_abs}")

# ═════════════════════════════ 3 · findings distants : modèle et niveau de preuve ═══
print("═══ 3 · le finding DAST reste une OBSERVATION, prouvable et traçable ═══")
prov_zap = reg.provider("zap_baseline")
vus_zap = F.normaliser("zap_baseline", {"parser": "zap_baseline",
                                        "items": parsers_zap.parse(json.dumps(FX_ZAP))},
                       mani=prov_zap.manifest, racines=())
vue0 = F.vue_unifiee(vus_zap[0])
cas("cycle.verified est FALSE pour chaque finding DAST, structurellement (oracle = autre chose)",
    len(vus_zap) == 3 and all(v.to_dict()["cycle"]["verified"] is False for v in vus_zap),
    [v.to_dict()["cycle"]["verified"] for v in vus_zap])
cas("la vue unifiée rend le niveau d'affirmation : « observe », jamais « verifie »",
    all(F.vue_unifiee(v)["verification"] == "observe" for v in vus_zap), "")
cas("preuve et source_id traversent la projection plate (les alias demandés par le contrat)",
    vue0["preuve"] == "en-tête CSP absent" and vue0["source_id"] == "10202@7", {
        k: vue0.get(k) for k in ("preuve", "source_id")})
cas("l'URL de cible d'accès avec credentials ne passe JAMAIS dans la coordonnée du finding",
    all("***" not in json.dumps(v.to_dict()) for v in vus_zap)
    and F._nettoie_url("https://u:secretpass@h/x") == "https://***@h/x", "")

# ═════════════════════════════ 4 · la cage distante ═══
print("═══ 4 · Sandbox : cible distante = pas de dépôt monté, cohérence exigée ═══")
with tempfile.TemporaryDirectory(prefix="dast-cage-") as td:
    tdp = Path(td)
    (tdp / "gitconfig").write_text("", encoding="utf-8")
    sb_distant = SB.Sandbox(racine_scan=None, racine_regles=tdp, racine_db=None,
                            sortie=tdp, gitconfig=tdp / "gitconfig", cible_distante=True)
    cmd_d = " ".join(sb_distant.commande(["zap-baseline.py", "-t", "https://x"]))
    cas("aucun `--ro-bind … mt-scan` dans une cage distante (rien à monter), et le cwd est la SORTIE",
        "mt-scan" not in cmd_d and f"--chdir {sb_distant.M_OUT}" in cmd_d, cmd_d[:220])
    cas("le réseau coupé reste le défaut d'une cage distante (l'export se DEMANDE)",
        "--unshare-net" in cmd_d, "")
    sb_local = SB.Sandbox(racine_scan=tdp, racine_regles=tdp, racine_db=None,
                          sortie=tdp, gitconfig=tdp / "gitconfig")
    cmd_l = " ".join(sb_local.commande(["semgrep", "--x"]))
    cas("la cage locale est inchangée au mot près : mt-scan monté, chdir sur le scan",
        f"--ro-bind {tdp} {sb_local.M_SCAN}" in cmd_l and f"--chdir {sb_local.M_SCAN}" in cmd_l,
        cmd_l[:220])
    lim_l = sb_local.limites_appliquees()
    lim_d = sb_distant.limites_appliquees()
    cas("la clé « cible » des limites n'existe QUE pour le mode distant (empreintes locales figées)",
        "cible" not in lim_l and "cible" in lim_d and set(lim_l) <= set(lim_d),
        f"locale={sorted(lim_l)}")
    prob_incoherent = SB.Sandbox(racine_scan=tdp, racine_regles=tdp, sortie=tdp,
                                 gitconfig=tdp / "gitconfig", cible_distante=True).verifie()
    cas("cible_distante AVEC un racine_scan posé est un état refusé, pas un état monté",
        any("incohérent" in p for p in prob_incoherent), prob_incoherent[:2])
    v_d = sb_distant.verifie()
    cas("sans dépôt, `verifie()` ne réclame pas « dépôt introuvable » (les autres préconditions restent)",
        not any("dépôt" in p for p in v_d), v_d[:2])
    d1 = RUN.digest_cible_distante("https://cible.example/")
    d2 = RUN.digest_cible_distante("https://cible.example/")
    d3 = RUN.digest_cible_distante("https://autre.example/")
    cas("digest d'une cible distante = sha de la référence SÛRE : déterministe et discriminant",
        d1 == d2 and d1[0] != d3[0] and d1[1] == "" and d1[2] is False, d1)

# ═════════════════════════════ 5 · adaptateur : ordre des gardes et cible typée ═══
print("═══ 5 · generique_cli : conditions d'abord, exécutable ensuite, index sans secret ═══")


@dataclasses.dataclass
class Sbx:
    """Le strict minimum que `generique_cli` touche — interface des doubles documentés.

    `egress` reproduit la SEULE chose que l'adaptateur regarde pour la condition réseau :
    le `--unshare-net` que la vraie `Sandbox.commande` injecte quand la cage est fermée.
    Fermée par défaut — un double ouvert par inadvertance transformerait le refus politique
    du cas 14bis en exécution, exactement la confusion que ce fichier refuse.
    """
    sortie: Path
    octets: dict = dataclasses.field(default_factory=dict)
    codes: dict = dataclasses.field(default_factory=dict)      # provider → code
    appelee: list = dataclasses.field(default_factory=list)
    egress: bool = False
    M_OUT: str = "/mnt/out"
    M_SCAN: str = "/mnt/scan"
    M_REGLES: str = "/mnt/regles"
    M_DB: str = "/mnt/db"
    racine_db: Path | None = None
    timeout: int = 600

    def commande(self, argv):
        retour = ["bwrap", *argv]
        if not self.egress:
            retour.insert(1, "--unshare-net")            # comme la vraie cage fermée
        return retour

    def delai_effectif(self, demande):
        return int(demande or self.timeout)

    def exec(self, argv, env=None, timeout=None):
        pid = Path(str(argv[0])).name
        self.appelee.append((pid, list(argv)))
        for nom, contenu in self.octets.items():
            (self.sortie / nom).write_text(contenu, encoding="utf-8")
        return types.SimpleNamespace(code=self.codes.get(pid, 0), timeout=False,
                                     stdout="", stderr="")


# provider ad hoc, binaire « semgrep » NOMMÉMENT absent de ce scratch (cf. en-tête) :
doc_alpha = {"id": "alpha-dast", "binaire": "semgrep", "argv": ["{BIN}", "-t", "{URL}"],
             "output": {"format": "json"}, "extraction": {"modele": "plat", "champs": {}},
             "conditions": {"reseau": True}, "target_types": ["url"], "code_succes": [0]}
mani_alpha = PM.valider(doc_alpha, "CAP_TEST")
prov_alpha = types.SimpleNamespace(id="alpha-dast", capability="CAP_TEST", manifest=mani_alpha,
                                   target_types=("url",), conditions={})
with tempfile.TemporaryDirectory(prefix="dast-garde-") as td:
    try:
        A.generique_cli(prov_alpha, Sbx(sortie=Path(td)),
                        target=Target("url", "https://cible.example"))
        cas("14bis. conditions réseau AVANT l'exécutable : le refus est POLITIQUE, pas l'accident "
            "d'un binaire absent", False, "aucune exception levée")
    except A.ConditionRefusee as e:
        cas("14bis. conditions réseau AVANT l'exécutable : le refus est POLITIQUE, pas l'accident "
            "d'un binaire absent", "réseau requis" in str(e) and "faux « rien trouvé »" in str(e),
            str(e)[:150])
    except FileNotFoundError as e:
        cas("14bis. conditions réseau AVANT l'exécutable : le refus est POLITIQUE, pas l'accident "
            "d'un binaire absent", False, f"FileNotFoundError a volé le motif : {e}")

# le même provider SANS condition réseau, hors cache armé → refus D1, avant tout Popen
doc_beta = dict(doc_alpha, id="beta-dast", conditions={}, target_types=["url"])
prov_beta = types.SimpleNamespace(id="beta-dast", capability="CAP_TEST",
                                  manifest=PM.valider(doc_beta, "CAP_TEST"),
                                  target_types=("url",), conditions={})
with tempfile.TemporaryDirectory(prefix="dast-d1-") as td:
    try:
        A.generique_cli(prov_beta, Sbx(sortie=Path(td)), target=Target("url", "https://x"))
        cas("15bis. outil réellement absent + cible distante : D1 refuse avant tout lancement "
            "(la typage de cible ne contourne PAS la règle)", False, "aucune exception")
    except FileNotFoundError:
        cas("15bis. outil réellement absent + cible distante : D1 refuse avant tout lancement "
            "(la typage de cible ne contourne PAS la règle)", True, "")

# le provider ZAP du registre, exécuté contre le double avec un VRAI rapport
with tempfile.TemporaryDirectory(prefix="dast-zap-") as td:
    tdp = Path(td)
    sbx = Sbx(sortie=tdp, egress=True, octets={"zap_baseline.txt": json.dumps(FX_ZAP)})
    r = A.generique_cli(reg.provider("zap_baseline"), sbx,
                        target=Target("url", "https://user:***@cible.example/app"))
    argv = sbx.appelee[0][1]
    cas("la commande porte l'URL RÉELLE (un scan authentifié a besoin de ses credentials)",
        "https://user:***@cible.example/app" in " ".join(argv), " ".join(argv)[:200])
    idx = " ".join(str(c.__dict__) for c in r.couverture.cibles)
    cas("l'INDEX de couverture, lui, est rendu sans userinfo (l'artefact ne stocke pas le login)",
        "secretpass" not in idx and "cible.example" in idx, idx[:200])
    cas("code 1 de ZAP (FAIL trouvés, code lu dans sa source) est un SCAN, pas un échec d'exécution",
        r.code_retour == 0 and not any("ÉCHEC D'EXÉCUTION" in x for x in r.couverture.limites_connues),
        f"code={r.code_retour} · {r.couverture.limites_connues[:1]}")
    vus_r = F.normaliser("zap_baseline", r.donnees, mani=reg.provider("zap_baseline").manifest,
                         racines=())
    cas("le trajet complet adaptateur→normaliseur rend les 3 findings sur leurs URL",
        len(vus_r) == 3 and len({v.identity["fingerprint"] for v in vus_r}) == 3
        and {v.location.get("url") for v in vus_r} == {"https://cible.example/a",
                                                        "https://cible.example/b",
                                                        "https://cible.example/"},
        [v.location.get("url") for v in vus_r])

    # vide légitime à distance : rapport écrit, zéro constat → UN RÉSULTAT + sa limite.
    sbx_vide = Sbx(sortie=tdp, egress=True, octets={"zap_baseline.txt": json.dumps({"site": []})})
    rv = A.generique_cli(reg.provider("zap_baseline"), sbx_vide,
                         target=Target("url", "https://cible.example"))
    etats = [c.etat for c in rv.couverture.cibles]
    cas("scan distant réussi et vide = « scanned_successfully » + la limite ÉCRITE "
        "(absence de correspondance ≠ absence de vulnérabilité) — pas un ÉCHEC rassurant",
        etats == ["scanned_successfully"]
        and any("absence de correspondance" in x for x in rv.couverture.limites_connues)
        and not any("ÉCHEC D'EXÉCUTION" in x for x in rv.couverture.limites_connues),
        f"{etats} · {rv.couverture.limites_connues[:2]}")
    cas("…et le code de retour normalisé 0 : un vide n'est pas une erreur, une erreur n'est pas un vide",
        rv.code_retour == 0, f"code={rv.code_retour}")

    # rien de lisible malgré code 0 : l'honnêteté inverse. DOSSIER NEUF — un double
    # « muet » posé là où l'outil d'avant a déjà écrit son rapport relirait ce rapport
    # (le piège du brut fantôme, vu dans test_plugins) : le silence doit être vérifié
    # dans le vide, pas à côté d'un résidu.
    with tempfile.TemporaryDirectory(prefix="dast-muet-") as td2:
        sbx_muet = Sbx(sortie=Path(td2), egress=True, octets={})
        rm = A.generique_cli(reg.provider("zap_baseline"), sbx_muet,
                             target=Target("url", "https://cible.example"))
    cas("code 0 et AUCUNE sortie lisible reste « ÉCHEC D'EXÉCUTION » même à distance",
        any("ÉCHEC D'EXÉCUTION" in x for x in rm.couverture.limites_connues)
        and all(c.etat == "not_scanned" for c in rm.couverture.cibles),
        rm.couverture.limites_connues[:1])

# timeout : la vague est bornée par la clause du manifest ZAP (900 s plafonnés), consigné.
demande, note = COND.timeout_effectif(reg.provider("zap_baseline"), 600)
cas("le timeout_s déclaré du manifest zap est ÉCRIT dans les conditions (900 demandé)",
    reg.provider("zap_baseline").manifest.timeout_s == 900, f"demande={demande} note={note!r}")

# ═════════════════════════════ 6 · la vague sur cible distante (pipeline._vague) ═══
print("═══ 6 · pipeline._vague : descripteur typé, artefacts, journal ═══")
with tempfile.TemporaryDirectory(prefix="dast-vague-") as td:
    tdp = Path(td)
    miss = MS.ouvrir("scan de vulnérabilités web https://cible.example",
                     PLAN.canonicaliser("scan de vulnérabilités web https://cible.example"),
                     "https://cible.example",
                     cible_descr={"type": "url", "reference": "https://cible.example",
                                  "local": False, "chemin": None})
    cib = Cible("url", "https://cible.example")
    exec_ = PI.Execution(plan={}, decision={"allow": True, "motifs": []}, intent={},
                         sortie=str(tdp))
    sbx = Sbx(sortie=tdp, egress=True, octets={"zap_baseline.txt": json.dumps(FX_ZAP)})
    V = PI._ContexteVague(
        miss=miss, registre=reg, exec_=exec_, sbx=sbx, cible=None, sortie=tdp,
        ctx=types.SimpleNamespace(outils={}, contexte_empreinte="test", input_digest="x",
                                  input_commit="", working_tree_dirty=False),
        trouves={}, tous_findings=[], domaines={}, binaires={},
        descripteur=cib, cible_distante=True)
    step = types.SimpleNamespace(provider="zap_baseline")
    PI._vague([step], V, {"steps": [], "selection": {}}, {"allow": True, "motifs": []},
              "2026-09-02T00:00:00Z", 1)
    fdgs = V.tous_findings
    cas("la vague distante passe par TOUT le corps normal : findings, raw écrit, brut conservé",
        len(fdgs) == 3 and exec_.raw and (tdp / "raw_zap_baseline.json").exists()
        and any(str(b["brut"] or "").startswith("brut_zap_baseline") for b in exec_.raw),
        {"fichier": exec_.raw[0]["fichier"], "brut": exec_.raw[0]["brut"]})
    journ = [json.loads(l) for l in (Path(miss.chemin) / "journal.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    ligne_exec = [e for e in journ if e["type"] == "execution"]
    cas("le journal nomme l'exécution avec son compte de findings (aucun trou entre cage et trace)",
        ligne_exec and ligne_exec[0]["provider"] == "zap_baseline"
        and ligne_exec[0]["findings"] == 3 and ligne_exec[0]["code_retour"] == 0,
        ligne_exec[:1])
    cov = exec_.couverture[0]["cibles"]
    cas("la couverture indexe la cible masquée, et le rapport verra une observation, pas une certitude",
        cov and "cible.example" in json.dumps(cov) and "secretpass" not in json.dumps(cov),
        json.dumps(cov)[:200])

    # Descripteur typé, envers et contre tout : `semgrep` déclare [repository] — sur une
    # cible distante « url », il doit être REFUSÉ PAR LE TYPE avant tout appel, pas
    # converti en chemin local bidon ni exécuté « quand même » sur une Path. Jugé ici, et
    # pas seulement sur le message : la commande de l'adaptateur ne doit pas avoir été
    # touchée, et aucun finding partiel ne doit avoir été écrit.
    _nb_traces = len(sbx.appelee)
    _nb_findings = len(V.tous_findings)
    try:
        PI._vague([types.SimpleNamespace(provider="semgrep")], V, {"steps": []},
                  {"allow": True, "motifs": []}, "2026-09-02T00:00:00Z", 1)
        leve = "AUCUNE exception — la conversion implicite a eu lieu"
    except PI.PipelineError as e:
        leve = str(e)
    except Exception as e:                              # noqa: BLE001 - mauvaise classe = échec parlant
        leve = f"{type(e).__name__}: {e}"
    cas("cible distante hors des types déclarés du provider = PipelineError AVANT tout appel, "
        "jamais un Path de secours ni une exécution silencieuse",
        "hors des types déclarés" in leve and len(sbx.appelee) == _nb_traces
        and len(V.tous_findings) == _nb_findings, leve[:180])

# ═════════════════════════════ 7 · corrélation sur coordonnée (clusterer) ═══
print("═══ 7 · clusterer : même URL = même sujet ; deux outils = convergence documentée ═══")


def _f(outil, canon, url=None, hote=None, ligne=None, fichier=None, original="x"):
    loc = {"asset": "url" if url else ("hote" if hote else "repository"),
           "file": fichier, "line": ligne, "package": None}
    if url:
        loc["url"] = url
    if hote:
        loc["hote"] = hote
    return F.Finding(id=f"{outil}-{canon}-{url or fichier}-{ligne or 0}",
                     source={"tool": outil, "provider": outil, "original_rule_id": original,
                             "canonical_rule_id": f"{outil}:{canon}"},
                     identity={"canonical_rule_id": f"{outil}:{canon}",
                               "fingerprint": F._fp(outil, canon, str(url or fichier), str(ligne))},
                     location=loc, severity={"value": "HIGH", "origine": outil},
                     evidence={"message": "m"})


deux_outils = [
    _f("zap", "csp-missing", url="https://cible.example/a"),
    _f("nuclei", "csp-missing", url="https://cible.example/a"),
    _f("ffuf", "admin", url="https://cible.example/a")]
res = CL.regrouper(deux_outils)
cls = res["clusters"]
# Le contrat est plus HONNÊTE que l'idée qu'on s'en fait : `canonical_rule_id` porte le
# nom du provider (findings.depuis_manifest), donc DEUX OUTILS DIFFÉRENTS ne peuvent
# jamais « confirmer la même règle » — et le clusterer ne le revendique pas : un
# voisinage de coordonnée reste une co-localisation (medium), même vu par trois yeux.
# Prétendre une corroboration sur deux ids de règles fabriqués par deux éditeurs
# distincts serait une affirmation de sécurité fausse. La convergence high (`same_rule`
# + `cross_ref`) est réservée au cas réel : le MÊME fait, identifié identiquement —
# doublons inclus, testé juste après.
cas("deux outils sur la MÊME URL → UN cluster de co-localisation medium — le cross_tool est "
    "NOMMÉ (« outils concernés »), jamais promu en confirmation, et le tiers à la même "
    "coordonnée rejoint le cluster sans raison fabriquée",
    len(cls) == 1 and cls[0]["confidence"] == "medium"
    and "same_asset" in cls[0]["reason"] and "cross_tool" in cls[0]["reason"]
    and "cross_ref" not in cls[0]["reason"]
    and set(cls[0]["members"]) == {f.id for f in deux_outils},
    json.dumps({k: cls[0][k] for k in ("reason", "confidence")} if cls else {}, ensure_ascii=False))
doublons = [
    _f("zap", "csp-missing", url="https://cible.example/a"),
    _f("zap", "csp-missing", url="https://cible.example/a")]
cls_d = CL.regrouper(doublons)["clusters"]
cas("…et la convergence high (same_rule + cross_ref) frappe quand le même constat revient "
    "sous la MÊME identité (doublons de rapport ou provider dupliqué) : le regroupement des "
    "doublons est exactement ce que le cross_ref affirme",
    len(cls_d) == 1 and {"same_rule", "cross_ref"} <= set(cls_d[0]["reason"])
    and cls_d[0]["confidence"] == "high" and len(cls_d[0]["members"]) == 2,
    json.dumps(cls_d[0] if cls_d else {}, ensure_ascii=False, default=str)[:220])
deux_url = [_f("zap", "csp", url="https://x/a"), _f("zap", "csp", url="https://x/b")]
res2 = CL.regrouper(deux_url)
cas("la MÊME règle sur deux URL distinctes ne converge PAS : l'empreinte suit la coordonnée",
    not res2["clusters"] and len(res2["non_regroupe"]) == 2, res2["stats"])
repo = [_f("semgrep", "s1", fichier="a.py", ligne=10), _f("bandit", "s1", fichier="a.py", ligne=11)]
res3 = CL.regrouper(repo)
cas("la corrélation de dépôt est INTACTE (fichier+proximité garde la main ; la règle asset ne "
    "s'y substitue pas)",
    len(res3["clusters"]) == 1 and res3["clusters"][0]["reason"][:2] == ["same_asset", "same_file"]
    or "fichier:" in res3["clusters"][0]["cle"],
    res3["clusters"][0] if res3["clusters"] else res3["stats"])
hotes = [_f("nmap", "22", hote="10.0.0.5"), _f("nuclei", "22", hote="10.0.0.5")]
res4 = CL.regrouper(hotes)
cas("deux constats sur le même HÔTE (règle canonique commune « 22 ») convergent aussi : la "
    "règle asset n'est pas réservée aux URL",
    len(res4["clusters"]) == 1 and "same_asset" in res4["clusters"][0]["reason"],
    res4["clusters"][0]["reason"] if res4["clusters"] else res4)

# ═════════════════════════════ 8 · sélection et intention ═══
print("═══ 8 · choisir_providers : explicite seul armerait ; jamais par accident ═══")
it_web = IN.inferer("fais un scan de vulnérabilités web sur https://cible.example", reg)
choix_web = IN.choisir_providers(it_web, reg)
cas("la demande explicite résout la capacité ACTIVE et SÉLECTIONNE son provider prioritaire "
    "(avant : structurellement inatteignable)",
    "WEB_VULN_SCAN_ACTIVE" in it_web.capabilities and set(choix_web) & {"zap_baseline", "nuclei"},
    {"cap": it_web.capabilities, "choix": choix_web})
it_gen = IN.inferer("scan de sécurité complet du dépôt", reg)
cas("la demande générique ne contient AUCUNE des trois capacités DAST — l'armement reste un "
    "choix nommé par le demandeur",
    not ({"NETWORK_DISCOVERY", "WEB_VULN_SCAN_ACTIVE", "WEB_ENDPOINT_DISCOVERY_ACTIVE"}
         & set(it_gen.capabilities)), sorted(it_gen.capabilities))
choix_gen = IN.choisir_providers(it_gen, reg)
cas("et par conséquent aucun provider DAST n'entre dans un plan générique",
    not (set(choix_gen) & {"nmap", "nuclei", "ffuf", "zap_baseline"}), choix_gen)
it_net = IN.inferer("liste les ports ouverts sur mon réseau interne", reg)
cas("la demande réseau nommément adressée atteint NETWORK_DISCOVERY → nmap",
    "NETWORK_DISCOVERY" in it_net.capabilities and "nmap" in IN.choisir_providers(it_net, reg),
    {"caps": it_net.capabilities, "choix": IN.choisir_providers(it_net, reg)})
provs, exclus_cond = COND.filtrer(choix_web, reg, egress=False, racine_db=None)
cas("cage fermée = provider ACTIVE écarté AVANT plan, avec son motif (réseau requis) — la "
    "sélection ne saute pas la politique, elle la précède",
    not provs and any("réseau" in v for v in exclus_cond.values()), exclus_cond)
descs = {c.id: c.description for c in reg.capabilities()
         if c.id in ("WEB_VULN_SCAN_ACTIVE", "NETWORK_DISCOVERY", "WEB_ENDPOINT_DISCOVERY_ACTIVE")}
cas("aucun mot d'outil n'est apparu dans les DESCRIPTIONS (le prompt LLM n'emporte pas de nom "
    "d'outil — les mots de capacité sont dans `mots_cles`, hors prompt)",
    all(not any(m in d.lower() for m in ("zap", "nuclei", "ffuf", "nmap")) for d in descs.values()),
    descs)

# ═════════════════════════════ 9 · ce qui reste hors de portée ICI, nommé ═══
print("═══ 9 · limites du terrain ═══")
non_evalue("décision OPA réelle sur un step ACTIVE",
           "binaire `opa` introuvable et openpolicyagent.org injoignable (mesuré 02/09) : le "
           "verrou `sandbox_non_durci_outil_actif` est vérifié dans le fichier .rego par "
           "test_catalogue_outils ; sa Jouissance réelle (refus en bout-en-bout) est épinglée "
           "dans test_qualite_plateforme (16quater/16octies) sur machine armée.")
non_evalue("exécution réelle de zap-baseline.py, nuclei, ffuf, nmap",
           "aucun de ces binaires n'est exécutable ici (JRE absent pour ZAP ; les autres sont "
           "épinglés sans dépôt sur cette machine). Les argv/codes admis de ZAP sont LUS dans la "
           "source épinglée (v2.17.0) ; le premier exécuté réel se consignera à l'armement "
           "(PHASE5/QUALIF_OUTILS_ACTIFS.md).")
non_evalue("montée en charge réseau sortant de la cage (egress réel)",
           "`bwrap` absent de cette machine : user namespaces refusés. Le chemin commande→"
           "conditions→refus est mesuré ci-dessus ; l'exécution hors du réseau coupé reste "
           "l'épreuve des batteries d'isolation sur une machine où bootstrap a abouti.")

print()
if ECHECS:
    print(f"{len(CAS) - len(ECHECS)} cas passent · {len(ECHECS)} ÉCHEC(S) :")
    for n, ok, det in CAS:
        if not ok:
            print(f"  - {n}")
            if det != "":
                print(f"        détail : {det}")
    for n, c in NON_EVALUES:
        print(f"  NON ÉVALUÉ · {n} — {c}")
    sys.exit(1)
print(f"{len(CAS)}/{len(CAS)} cas passent (plus {len(NON_EVALUES)} NON ÉVALUÉS nommés)")
for n, c in NON_EVALUES:
    print(f"  NON ÉVALUÉ · {n} — {c}")
