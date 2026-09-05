#!/usr/bin/env python3
"""Plugins G4 (TLS & path traversal) : registre + planification + interprétation.

Aucun réseau : les sorties sont celles ARCHIVÉES dans cible_web/qualif/<outil>/
(épreuves réelles du 2026-09-05 contre THAUMAS-WEB) et deux FIXTURES étiquetés
(structure mesurée, valeurs synthétiques — sslscan « surface présente », tlsx JSONL).

Ce que la batterie prouve :
  1. les 5 épingles G4 se lisent (outils.registre) et les 5 plugins se chargent ;
  2. `planifier` résout l'argv (URL substituée, codes de succès déclarés ; forme
     hôte:port {HOSTPORT} pour sslscan/sslyze — port par défaut du schéma restauré) ;
  3. l'interpréteur retrouve les items depuis les sorties RÉELLES archivées —
     y compris les refus nommés (TLS sur cible HTTP pur : échec nommé, jamais un
     « scan propre ») et la faille trouvée (dotdotpwn, T-TRAVERSAL-001) ;
  4. le chemin TLS POSITIF est MESURÉ (2026-09-05, mode --tls de serveur.py sur
     127.0.0.1:8443, cert auto-signé CN=thaumas-web-epreuve) : les 4 outils TLS
     rendent des items depuis les archives *_https — sslscan_https.xml (2 protocoles
     enabled=1 + 16 suites offertes), sslyze_https.json (18 commandes, scan
     COMPLETED), testssl_sh_https.json (166 entrées, sévérités DÉCLARÉES portées
     telles quelles), tlsx_https.txt (1 enregistrement, probe_status booléen).
     Sorties produites par executer_qualif_tls.py (binaires épinglés à
     /home/julie/.cache/arena_secops/bin), documentées par les attendus_tls.yaml
     de chaque dossier — le chemin « surface présente » n'est plus un simple fixture.

Usage : python PHASE3/test_plugins_g4.py   (exit 0/1)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

QUALIF = RACINE / "cible_web" / "qualif"
URL_CIBLE = "http://127.0.0.1:8807"

CAS: list[tuple[str, bool | None, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, None if cond is None else bool(cond), detail))
    if not cond and cond is not None:
        ECHECS.append(nom)


def _lire(*parties: str) -> str:
    return (QUALIF.joinpath(*parties)).read_text(encoding="utf-8")


# FIXTURE sslscan — structure MESURÉE (qualif/sslscan/sslscan_xml_hostport_reference.txt,
# refus de négociation), valeurs synthétiques. Le chemin « surface présente » est AUSSI
# mesuré sur la sortie réelle (sslscan_https.xml — section 4) ; le fixture reste pour la
# tolérance du parser (renégociation insécurisée, suite rejetée ignorée), étiqueté comme tel.
SSLSCAN_XML_SURFACE = """<?xml version="1.0" encoding="UTF-8"?>
<document title="SSLScan Results" version="2.1.5" web="http://github.com/rbsec/sslscan">
 <ssltest host="exemple.test" sniname="exemple.test" port="443">
  <protocol type="ssl" version="2" enabled="0" />
  <protocol type="tls" version="1.2" enabled="1" />
  <ciphersuite count="2">
   <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384" id="0xC030" />
   <cipher status="rejected" sslversion="TLSv1.2" bits="0" cipher="NULL-SHA256" id="0x00B0" />
  </ciphersuite>
  <renegotiation supported="1" secure="0" />
 <certificates>
 </certificates>
 </ssltest>
</document>"""

# FIXTURE tlsx — structure MESURÉE du binaire épinglé (qualif/tlsx/tlsx_https.txt :
# probe_status booléen, tls_version, cipher, subject_cn/issuer_cn, self_signed — PAS
# cipher_suite ni « tls-open », jamais mesurés sur le binaire), VALEURS SYNTHÉTIQUES,
# étiqueté comme tel.
TLSX_JSONL = json.dumps({"host": "exemple.test", "port": "443", "probe_status": True,
                         "tls_version": "tls13", "cipher": "TLS_AES_256_GCM_SHA384",
                         "subject_cn": "exemple.test", "issuer_cn": "exemple.test",
                         "self_signed": True}) + "\n"


def main() -> int:
    # ─────────────────────────────────────── 1. épingles & chargement des plugins
    import outils
    reg_tools = outils.registre()
    for tid, version in (("testssl.sh", "3.2.4"), ("sslyze", "6.3.1"),
                         ("sslscan", "2.1.5"), ("tlsx", "1.3.0"), ("dotdotpwn", "3.0.2")):
        t = reg_tools.get(tid)
        cas(f"épingle {tid} porte {version}", t is not None and t.version == version
            and t.role == "outil", f"lu : {t.version if t else 'ABSENT'}")
    for tid in ("testssl.sh", "sslscan", "tlsx", "dotdotpwn"):
        t = reg_tools.get(tid)
        cas(f"épingle {tid} : empreinte binaire réelle (pas un placeholder)",
            t is not None and len(t.sha256) == 64 and set(t.sha256) != {"0"},
            t.sha256[:16] if t else "absent")

    import parsers
    echecs = parsers.echecs_import()
    cas("aucun parser en échec d'import", not echecs, json.dumps(echecs))
    for nom in ("sslscan", "sslyze", "dotdotpwn"):
        cas(f"parser {nom} enregistré", parsers.obtenir(nom) is not None)

    from registre import Registry
    reg_ok = True
    try:
        reg = Registry()
    except Exception as e:                                 # noqa: BLE001
        reg, reg_ok = None, None                           # type: ignore
        cas("registre lisible ici", None, f"NON ÉVALUÉ : {type(e).__name__}: {e}")

    priorites: list[int] = []
    if reg_ok:
        for pid in ("testssl_sh", "sslyze", "sslscan", "tlsx", "dotdotpwn"):
            prov = reg.provider(pid)
            cas(f"provider {pid} chargé, cibles ['url']",
                prov is not None and list(prov.manifest.cibles) == ["url"],
                f"cibles={list(prov.manifest.cibles) if prov else 'ABSENT'}")
            if prov is not None:
                priorites.append(prov.priorite)
        cas("priorités G4 distinctes et dans [120, 160]",
            len(priorites) == len(set(priorites))
            and all(120 <= p <= 160 for p in priorites),
            f"priorités={sorted(priorites)}")

        # ─────────────────────────────── 2. planification : l'argv se résout
        import fournisseurs_web as FW
        attendus_argv = {
            "testssl_sh": ("--jsonfile", "{URL} absent, cible en dernier"),
            "sslyze": ("--json_out", "'-' : JSON sur stdout"),
            "sslscan": ("--xml=-", "XML sur stdout"),
            "tlsx": ("-j", "-o {OUT}"),
            "dotdotpwn": ("TRAVERSAL", "-u {URL}/download?file=TRAVERSAL"),
        }
        # sslscan et sslyze refusent une URL (mesuré) : leur cible passe en forme
        # hôte:port — le jeton {HOSTPORT} du cœur (port par défaut du schéma restauré),
        # PAS l'URL ; les trois autres gardent {URL}.
        forme_hostport = {"sslscan", "sslyze"}
        for pid, (fragment, _) in attendus_argv.items():
            try:
                plan = FW.planifier(pid, URL_CIBLE, "/tmp/agnt-g4-test", egress=True,
                                    registre=reg)
                argv_str = json.dumps(plan["argv"], ensure_ascii=False)
                if pid in forme_hostport:
                    cible_ok = "127.0.0.1:8807" in argv_str and URL_CIBLE not in argv_str
                else:
                    cible_ok = URL_CIBLE in argv_str
                cas(f"plan {pid} : argv résolu avec {fragment}",
                    cible_ok and fragment in argv_str
                    and "{URL}" not in argv_str and "{OUT}" not in argv_str
                    and "{HOSTPORT}" not in argv_str
                    and plan["binaire_resolu"] is False,
                    argv_str[:110])
                cas(f"plan {pid} : code de succès déclaré",
                    plan["codes_succes"] == ([105] if pid == "dotdotpwn" else [0]),
                    str(plan["codes_succes"]))
            except Exception as e:                         # noqa: BLE001
                cas(f"plan {pid}", False, f"{type(e).__name__}: {e}")
            try:
                FW.planifier(pid, URL_CIBLE, "/tmp/agnt-g4-test", egress=False, registre=reg)
                cas(f"plan {pid} sans egress → refus nommé", False, "accepté")
            except FW.ErreurPlanification as e:
                cas(f"plan {pid} sans egress → refus nommé", "egress" in str(e), str(e)[:90])

    # ─────────────────── 3. interprétation des sorties RÉELLES archivées (sans réseau)
    if reg_ok:
        import fournisseurs_web as FW

        # — testssl.sh : refus d'usage (cible http://), JSON d'état relu, échec nommé
        brut = _lire("testssl.sh", "testssl_sh.json")
        r = FW.interpreter("testssl_sh", 254, brut, registre=reg)
        cas("testssl_sh : 3 entrées d'état relues du JSON (items_from \"$\")",
            len(r["items"]) == 3, f"items={len(r['items'])}")
        cas("testssl_sh : code 254 → échec NOMMÉ (pas un scan propre)",
            r["echec"] is True and "code 254" in r["motif"], r["motif"])
        severites = {f.severity.get("value") for f in r["findings"]} if r["findings"] else set()
        cas("testssl_sh : sévérités de scan portées telles quelles (FATAL/WARN, pas traduites)",
            {"FATAL", "WARN"} <= severites, f"severites={sorted(severites)}")

        # — sslyze : refus porté PAR LE JSON, code 0, 1 constat de l'outil
        r = FW.interpreter("sslyze", 0, _lire("sslyze", "sslyze.json"), registre=reg)
        cas("sslyze : 1 item lu du JSON archivé, code 0 → non-échec",
            len(r["items"]) == 1 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        if r["findings"]:
            f0 = json.dumps(r["findings"][0].to_dict(), ensure_ascii=False)
            cas("sslyze : constat = refus de l'OUTIL, mot pour mot, avec url",
                "sslyze-cible-refusee" in f0 and "Not a valid host:port" in f0
                and URL_CIBLE in f0, f0[:200])

        # — sslscan : refus de l'URL (code 1) + fixture « surface présente » (étiqueté)
        r = FW.interpreter("sslscan", 1, _lire("sslscan", "sslscan.xml"), registre=reg)
        cas("sslscan : sortie vide + code 1 → échec NOMMÉ",
            r["items"] == [] and r["echec"] is True and "code 1" in r["motif"], r["motif"])
        r = FW.interpreter("sslscan", 0, SSLSCAN_XML_SURFACE, registre=reg)
        regles = sorted(str(i.get("regle")) for i in r["items"])
        cas("sslscan fixture (étiqueté) : surface = 1 protocole + 1 cipher offert + renégociation",
            regles == ["sslscan-cipher", "sslscan-protocol", "sslscan-renegotiation"]
            and r["echec"] is False, f"regles={regles}")
        cas("sslscan fixture : la suite rejetée n'est PAS un constat (pas de bruit)",
            all("NULL-SHA256" not in json.dumps(i, ensure_ascii=False) for i in r["items"]),
            "")

        # — tlsx : vide silencieux NOMMÉ par le cœur + fixture JSONL (étiqueté)
        r = FW.interpreter("tlsx", 0, _lire("tlsx", "tlsx.txt"), registre=reg)
        cas("tlsx : sortie vide → échec nommé « pas un scan propre »",
            r["items"] == [] and r["echec"] is True
            and "sortie vide" in r["motif"] and "pas un scan propre" in r["motif"], r["motif"])
        r = FW.interpreter("tlsx", 0, TLSX_JSONL, registre=reg)
        cas("tlsx fixture (étiqueté) : 1 ligne JSONL → 1 item, url et règle mappées",
            len(r["items"]) == 1 and r["items"][0].get("host") == "exemple.test"
            and r["echec"] is False,
            json.dumps(r["items"], ensure_ascii=False)[:150])

        # — dotdotpwn : la faille TROUVÉE (T-TRAVERSAL-001), code 105 lu de la source
        r = FW.interpreter("dotdotpwn", 105, _lire("dotdotpwn", "dotdotpwn.txt"),
                           registre=reg)
        cas("dotdotpwn : 1 constat agrégé, code 105 (exit 31337 & 0xFF) → non-échec",
            len(r["items"]) == 1 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        if r["items"]:
            item = r["items"][0]
            preuve = str(item.get("preuve") or "")
            cas("dotdotpwn : confiance confirmée + CWE-22, sévérité absente",
                item.get("confiance") == "confirmée" and item.get("cwe") == "CWE-22"
                and "severite" not in item,
                json.dumps({k: item.get(k) for k in ("confiance", "cwe", "severite")},
                           ensure_ascii=False))
            cas("dotdotpwn : la preuve porte la séquence plantée T-TRAVERSAL-001",
                "download?file=../cible_web_secret/sauvegarde.txt" in preuve
                and URL_CIBLE in preuve, preuve[:160])
            cas("dotdotpwn : 14 traversals loggés, 13 URL distinctes agrégées (dédupe)",
                "13 séquence(s)" in str(item.get("message") or "")
                and _lire("dotdotpwn", "dotdotpwn.txt").count("<- VULNERABLE") == 14,
                f"message={item.get('message')} loggées="
                f"{_lire('dotdotpwn', 'dotdotpwn.txt').count('<- VULNERABLE')}")
        if r["findings"]:
            loc = json.dumps(r["findings"][0].location, ensure_ascii=False)
            cas("dotdotpwn : l'oracle retrouve l'url du constat (location.url)",
                URL_CIBLE in loc or "127.0.0.1" in loc, loc[:160])

        # — doctrine : un code hors succès reste un échec, même avec des items
        r = FW.interpreter("dotdotpwn", 0, _lire("dotdotpwn", "dotdotpwn.txt"), registre=reg)
        cas("dotdotpwn : code 0 (abort) hors succès [105] → échec nommé",
            r["echec"] is True and "code 0" in r["motif"], r["motif"])

        # ─────── 4. preuve TLS POSITIVE — archives *_https MESURÉES (2026-09-05, sans réseau)
        # Mode --tls de serveur.py sur 127.0.0.1:8443 (cert auto-signé CN=thaumas-web-epreuve)
        # : le chemin « surface présente » n'est plus un simple fixture à structure mesurée.
        # Archives produites par executer_qualif_tls.py (binaires épinglés au répertoire
        # des binaires promus), documentées par les attendus_tls.yaml de chaque dossier.

        # — planification sur la cible https : sslscan/sslyze en hôte:port, les autres
        #   gardent l'URL (formes mesurées des manifests)
        for pid, garde_url in (("sslscan", False), ("sslyze", False),
                               ("testssl_sh", True), ("tlsx", True)):
            plan_tls = FW.planifier(pid, "https://127.0.0.1:8443/", "/tmp/agnt-g4-test",
                                    egress=True, registre=reg)
            argv_tls = json.dumps(plan_tls["argv"], ensure_ascii=False)
            if garde_url:
                cas(f"plan TLS {pid} : l'URL https passe telle quelle",
                    "https://127.0.0.1:8443/" in argv_tls, argv_tls[:110])
            else:
                cas(f"plan TLS {pid} : forme hôte:port (127.0.0.1:8443), PAS l'URL",
                    "127.0.0.1:8443" in argv_tls
                    and "https://127.0.0.1:8443/" not in argv_tls, argv_tls[:110])

        # — _hote_port : le jeton {HOSTPORT}, port par défaut du schéma RESTAURÉ
        cas("_hote_port https://127.0.0.1:8443/ → 127.0.0.1:8443",
            FW._hote_port("https://127.0.0.1:8443/") == "127.0.0.1:8443", "")
        cas("_hote_port https://hote.tld/ → hote.tld:443 (port par défaut RESTAURÉ)",
            FW._hote_port("https://hote.tld/") == "hote.tld:443", "")
        cas("_hote_port http://127.0.0.1:8807/ → 127.0.0.1:8807",
            FW._hote_port("http://127.0.0.1:8807/") == "127.0.0.1:8807", "")

        # — sslscan MESURÉ : surface TLS offerte portée par le XML, AUCUNE sévérité
        r = FW.interpreter("sslscan", 0, _lire("sslscan", "sslscan_https.xml"), registre=reg)
        regles_tls = {str(i.get("regle")) for i in r["items"]}
        noms_tls = {str(i.get("nom_regle")) for i in r["items"]}
        cas("sslscan *_https MESURÉ : 18 items (2 protocoles enabled=1 + 16 suites offertes), échec False",
            len(r["items"]) == 18 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        cas("sslscan *_https : regles ⊆ {sslscan-protocol, sslscan-cipher}, « tls 1.3 » nommée",
            regles_tls <= {"sslscan-protocol", "sslscan-cipher"} and "tls 1.3" in noms_tls,
            f"regles={sorted(regles_tls)}")
        cas("sslscan *_https : TLS_AES_256_GCM_SHA384 présente, AUCUNE clé severite",
            any("TLS_AES_256_GCM_SHA384" in json.dumps(i, ensure_ascii=False)
                for i in r["items"])
            and all("severite" not in i and "severity" not in i for i in r["items"]), "")

        # — sslyze MESURÉ (manifest runtime, scans de sélection SANS --certinfo) :
        #   6 commandes exécutées → 6 items ; les commandes non demandées viennent à
        #   result: None et le parser n'en fait PAS de constat (mesuré). --certinfo est
        #   volontairement hors manifeste : le PEM du certificat déclenche le masquage
        #   des blobs base64 (≥ 40) et le JSON capturé devient illisible (mesuré) — le
        #   certificat est couvert par testssl.sh et tlsx.
        r = FW.interpreter("sslyze", 0, _lire("sslyze", "sslyze_https.json"), registre=reg)
        regles_tls = {str(i.get("regle")) for i in r["items"]}
        cas("sslyze *_https MESURÉ : 6 items (commandes exécutées du manifest), url=127.0.0.1:8443, échec False",
            len(r["items"]) == 6 and r["echec"] is False
            and {str(i.get("url")) for i in r["items"]} == {"127.0.0.1:8443"},
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        cas("sslyze *_https : les 6 commandes demandées, PAS certificate_info (hors manifeste)",
            {"sslyze-tls_1_2_cipher_suites", "sslyze-tls_1_3_cipher_suites",
             "sslyze-session_renegotiation", "sslyze-tls_compression",
             "sslyze-heartbleed", "sslyze-openssl_ccs_injection"} == regles_tls,
            f"regles={sorted(regles_tls)}")
        # Épreuve DIRECTE complète (hors manifeste, archivée) : 18 commandes dont 3 à
        # result: None (http_headers, session_resumption, tls_1_3_early_data) → 15
        # constats réels : le parser ne compte que ce qui a été exécuté (mesuré).
        r = FW.interpreter("sslyze", 0, _lire("sslyze", "sslyze_complet.json"), registre=reg)
        cas("sslyze épreuve complète (capacité, hors manifeste) : 15 constats réels sur 18 commandes — les result: None sont écartés",
            len(r["items"]) == 15
            and not any(str(i.get("regle")) in ("sslyze-http_headers",
                            "sslyze-session_resumption", "sslyze-tls_1_3_early_data")
                        for i in r["items"]),
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")

        # — testssl.sh MESURÉ : 166 entrées, sévérités DÉCLARÉES portées telles quelles
        r = FW.interpreter("testssl_sh", 0, _lire("testssl.sh", "testssl_sh_https.json"),
                           registre=reg)
        severites_tls = {f.severity.get("value") for f in r["findings"]}
        ids_tls = {str(i.get("id")) for i in r["items"]}
        cas("testssl_sh *_https MESURÉ : 166 entrées relues, échec False (code 0 ∈ succès)",
            len(r["items"]) == 166 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        cas("testssl_sh *_https : sévérités DÉCLARÉES portées telles quelles (CRITICAL et OK)",
            {"CRITICAL", "OK"} <= severites_tls, f"severites={sorted(severites_tls)}")
        cas("testssl_sh *_https : l'auto-signature est lue par l'OUTIL (cert_chain_of_trust, cert_commonName)",
            "cert_chain_of_trust" in ids_tls and "cert_commonName" in ids_tls,
            f"ids cert_* : {sorted(i for i in ids_tls if i.startswith('cert_'))}")

        # — tlsx MESURÉ : 1 enregistrement, auto-signature par RAPPROCHEMENT (artefact brut)
        r = FW.interpreter("tlsx", 0, _lire("tlsx", "tlsx_https.txt"), registre=reg)
        item_tls = r["items"][0] if r["items"] else {}
        finding_tls = r["findings"][0].to_dict() if r["findings"] else {}
        source_tls = finding_tls.get("source") or {}
        preuve_tls = finding_tls.get("evidence") or {}
        cas("tlsx *_https MESURÉ : 1 enregistrement JSONL → 1 item, échec False",
            len(r["items"]) == 1 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        cas("tlsx *_https : mapping mesuré (regle tls13, subject_cn/issuer_cn, preuve cipher)",
            source_tls.get("original_rule_id") == "tls13"
            and source_tls.get("nom_regle") == "thaumas-web-epreuve"
            and preuve_tls.get("message") == "thaumas-web-epreuve"
            and preuve_tls.get("preuve") == "TLS_AES_256_GCM_SHA384",
            json.dumps({"regle": source_tls.get("original_rule_id"),
                        "nom_regle": source_tls.get("nom_regle"),
                        "message": preuve_tls.get("message"),
                        "preuve": preuve_tls.get("preuve")}, ensure_ascii=False))
        cas("tlsx *_https : auto-signature lue par RAPPROCHEMENT (subject_cn == issuer_cn + self_signed)",
            item_tls.get("subject_cn") == item_tls.get("issuer_cn") == "thaumas-web-epreuve"
            and item_tls.get("self_signed") is True
            and item_tls.get("probe_status") is True, "")

    print(f"\n{'=' * 50}\n  {len(CAS) - len([c for c in CAS if c[1] is False]) - len([c for c in CAS if c[1] is None])}/{len(CAS)} passent"
          + (f" (+{len([c for c in CAS if c[1] is None])} NON ÉVALUÉS)" if any(c[1] is None for c in CAS) else "")
          + f"\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if cond is False:
            print(f"  ÉCHEC · {nom}\n        {detail}")
        elif cond is None:
            print(f"  NON ÉVALUÉ · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
