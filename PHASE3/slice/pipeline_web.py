"""Pipeline web : engagement → scope → plan → exécution → findings + preuve.

Assemble les pièces (web_scope, fournisseurs_web, orchestrateur, taches,
cycle_vie, preuve) SANS en dupliquer la logique. L'exécuteur est injecté :
`ExecuteurLocal` en prod, faux en tests. Aucun binaire réel requis ici —
`RUNTIME_VERIFIED = False` tant que le runtime Linux n'a pas tourné.

Un finding interprété naît OBSERVED (transition `observer` depuis DISCOVERED,
historique joint) : jamais CONFIRMED sans oracle (voir oracle_web).

Sortie fichier : un tool écrivant `{OUT}` (nuclei, ffuf, httpx…) consigne là sa
sortie déclarée. Le stdout, lui, peut être vide OU du bruit (ffuf -s imprime ses
matches en clair). Règle, identique au harnais : si le fichier déclaré existe,
son CONTENU est la sortie interprétée ; sinon, le stdout. Le fichier reste sur
disque comme artefact brut : la lecture n'efface rien.

Oracle (http_response) : les findings porteurs d'une URL DANS LE SCOPE sont
rejoués pour de vrai — N GET (3 normal, 5 aggressive) + un témoin (chemin
aléatoire du même hôte). La recette est le statut DÉCLARÉ par le tool quand il
en porte un (httpx → 200) ; sinon la recette « stabilité » (N rejeux
concordants + témoin discordant — le test anti-soft-404 : un serveur qui
répond 200 à tout est réfuté par son propre témoin). Verdict CONFIRMED →
candidater + verifier_ok (VERIFIED) ; REFUTED → rejeter (REJECTED) ;
POTENTIAL/INCONCLUSIVE → le finding reste OBSERVED, la raison est rendue.
Aucun corps de réponse n'est conservé (digest + taille, hygiène oracle_web).
"""
from __future__ import annotations

import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import fournisseurs_web as FW
import oracle_web as OW
import preuve as PR
import taches as TA
import web_scope as WS
from cycle_vie import DISCOVERED, transition
from orchestrateur import executer_plan

RUNTIME_VERIFIED = False

ORDRE_CHAINE = ["httpx", "katana", "ffuf", "nuclei"]


class ErreurPipeline(Exception):
    """Engagement inexploitable : scope, plan ou exécution nommés."""


def _rejouer(url: str, fois: int, timeout_s: float = 10.0):
    """N GET réels sur l'URL + 1 témoin (chemin aléatoire du même hôte).

    Hygiène oracle_web : le corps n'est JAMAIS conservé — digest + taille
    (ObservationRejeu). Une observation en erreur reste une observation : le
    jugement la compte, jamais l'inverse.
    """
    observations = []
    for _ in range(fois):
        try:
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "agnt-oracle/1 (rejeu)"})
            with urllib.request.urlopen(req, timeout=timeout_s) as r:
                observations.append(OW.ObservationRejeu.depuis_corps(r.status, r.read()))
        except urllib.error.HTTPError as e:
            try:
                corps = e.read()
            except Exception:                       # noqa: BLE001
                corps = None
            observations.append(OW.ObservationRejeu.depuis_corps(e.code, corps))
        except Exception as e:                      # noqa: BLE001
            observations.append(
                OW.ObservationRejeu(None, "", 0, False, f"{type(e).__name__}"))
    # Témoin : un chemin qui ne devrait rien porter sur le MÊME hôte. S'il répond
    # comme la cible, la « preuve » est générique → le jugement la réfute.
    parties = urlsplit(url)
    temoin_url = f"{parties.scheme}://{parties.netloc}/temoin-agnt-{uuid.uuid4().hex[:8]}"
    try:
        req = urllib.request.Request(temoin_url, method="GET",
                                     headers={"User-Agent": "agnt-oracle/1 (temoin)"})
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            temoin = OW.ObservationRejeu.depuis_corps(r.status, r.read())
    except urllib.error.HTTPError as e:
        try:
            corps = e.read()
        except Exception:                           # noqa: BLE001
            corps = None
        temoin = OW.ObservationRejeu.depuis_corps(e.code, corps)
    except Exception as e:                          # noqa: BLE001
        temoin = OW.ObservationRejeu(None, "", 0, False, f"{type(e).__name__}")
    return observations, temoin, temoin_url


def _verifier_par_oracle(findings: list[dict], engagement: dict) -> dict:
    """Rejeu RÉEL des findings web porteurs d'une URL (oracle http_response).

    Recette : le statut déclaré par le tool quand il en porte un (httpx → « 200 ») ;
    sinon « stabilité » — N rejeux concordants en statut ET en digest, témoin
    discordant. Sans URL, ou URL hors de l'hôte engagé : pas de rejeu, le finding
    reste OBSERVED et la raison est nommée. Le comptage rendu va au rapport.
    """
    fois = OW.REPLAY_PAR_INTENSITE.get(str(engagement.get("intensity") or "normal"), 3)
    hote_engage = str(engagement.get("hote") or "")
    compte = {"oracle": "http_response", "rejeu_reel": True, "rejeux_par_finding": fois,
              "verifies": 0, "rejetes": 0, "potentiels": 0, "inconclusifs": 0,
              "non_verifiables": 0}
    for f in findings:
        url_f = str((f.get("location") or {}).get("url") or "")
        if not url_f:
            f["verification"] = {"oracle": "http_response", "etat": "non_verifiable",
                                 "motif": "finding sans URL : rien à rejouer"}
            compte["non_verifiables"] += 1
            continue
        try:
            hote_f = WS.hote_de(url_f)
        except Exception:                           # noqa: BLE001
            hote_f = urlsplit(url_f).hostname or ""
        if hote_f != hote_engage:
            f["verification"] = {"oracle": "http_response", "etat": "hors_scope",
                                 "motif": f"URL hors de l'hôte engagé ({hote_engage}) : rejeu refusé"}
            compte["non_verifiables"] += 1
            continue
        observations, temoin, temoin_url = _rejouer(url_f, fois)
        regle = str((f.get("source") or {}).get("original_rule_id") or "")
        recette = "statut_declare" if regle.isdigit() else "stabilite"
        if recette == "statut_declare":
            expect = int(regle)
        else:
            premier = next((o.status for o in observations if o.status is not None), None)
            if premier is None:
                expect = 200                            # tout a échoué : juger le rendra INCONCLUSIVE
            else:
                expect = premier
        demande = OW.DemandeVerification(url=url_f, expect_status=expect,
                                         control_url=temoin_url,
                                         intensity=str(engagement.get("intensity") or "normal"))
        jugement = OW.juger(demande, observations, temoin)
        f["verification"] = {"oracle": "http_response", "recette": recette,
                             "url_rejouee": url_f, "temoin": temoin_url,
                             "jugement": jugement.to_dict(),
                             "observations": [{"status": o.status,
                                               "digest": o.body_digest[:12],
                                               "taille": o.body_taille,
                                               "erreur": o.erreur} for o in observations]}
        v = jugement.verdict.value
        if v == "confirmed":
            compte["verifies"] += 1
        elif v == "refuted":
            compte["rejetes"] += 1
        elif v == "potential":
            compte["potentiels"] += 1
        else:
            compte["inconclusifs"] += 1
        if jugement.cycle_evenement in ("verifier_ok", "rejeter"):
            hist = f["cycle"]["historique"]
            etat = f["cycle"]["etat"]
            e1 = transition(etat, "candidater")
            hist.append({"depuis": etat, "evenement": "candidater", "vers": e1})
            e2 = transition(e1, jugement.cycle_evenement)
            hist.append({"depuis": e1, "evenement": jugement.cycle_evenement, "vers": e2})
            f["cycle"] = {"etat": e2, "historique": hist}
    return compte


def derouler(engagement: dict, executer_tache, registre=None,
             out_dir: str = "/tmp/agnt-web", regles: str = "",
             verifier_oracle: bool = True) -> dict:
    """Déroule un engagement web planifié. Rend le rapport de mission (dict)."""
    if not isinstance(engagement, dict) or engagement.get("type") != "web":
        raise ErreurPipeline("engagement web attendu")
    url = engagement.get("url_canonique") or ""
    try:
        canonique = WS.canonicaliser_url(url)
    except Exception as e:
        raise ErreurPipeline(f"url inexploitable : {e}") from None
    if canonique != engagement.get("url_canonique"):
        raise ErreurPipeline("url_canonique incohérente avec l'engagement")
    garde = WS.ScopeEnforcer(autorises=[engagement.get("hote", "")], strict=True)
    ok, motif = garde.autoriser(canonique)
    if not ok:
        raise ErreurPipeline(f"scope : {motif}")
    egress = engagement.get("egress")
    egress_accorde = egress is True
    demandes = [p for p in ORDRE_CHAINE if p in (engagement.get("providers_prevus") or [])]
    demandes += [p for p in (engagement.get("providers_prevus") or []) if p not in ORDRE_CHAINE]
    plans, ecartes = [], []
    for pid in demandes:
        try:
            plans.append({**FW.planifier(pid, canonique, out_dir,
                                         egress=egress_accorde, registre=registre,
                                         regles=regles),
                          "provider_id": pid})
        except FW.ErreurPlanification as e:
            ecartes.append({"provider": pid, "motif": str(e)})
    if not plans and not ecartes:
        raise ErreurPipeline("aucun provider demandé")
    noeuds, precedent = [], None
    for plan in plans:
        nid = plan["provider_id"]
        noeuds.append({"id": nid, "depend_de": [precedent] if precedent else [],
                       "tache": TA.Tache(provider_id=nid, argv=plan["argv"],
                                         timeout_s=float(plan["timeout_s"] or 300))})
        precedent = nid
    run = executer_plan(noeuds, executer_tache)
    findings, details = [], []
    for res in run["taches"]:
        if res["etat"] != TA.TERMINEE:
            details.append({"provider": res["provider"], "etat": res["etat"],
                            "motif": (res["resultat"] or {}).get("erreur", "")})
            continue
        r = res["resultat"] or {}
        # Sortie fichier → stdout : voir docstring. Quand le manifest déclare une
        # sortie fichier et qu'elle existe, le FICHIER fait foi — même doctrine que
        # le harnais (fichier d'abord, stdout en repli). Le stdout n'y est pas toujours
        # vide pour autant : ffuf -s y imprime ses matches en clair (du bruit qui
        # n'est pas du JSON), et le prendre à la place du fichier serait interpréter
        # autre chose que la sortie déclarée. Un fichier absent n'est PAS une erreur
        # — l'outil avait le droit de tout dire sur stdout.
        plan = next((p for p in plans if p["provider_id"] == res["provider"]), None)
        stdout = r.get("stdout", "")
        if plan:
            brut = Path(out_dir) / plan.get("nom_sortie", "")
            try:
                if brut.is_file():
                    stdout = brut.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass                                  # stdout fait foi, motif le dira
        try:
            interp = FW.interpreter(res["provider"], r.get("code", -1),
                                    stdout, registre=registre)
        except FW.ErreurPlanification as e:
            details.append({"provider": res["provider"], "etat": "interpretation_impossible",
                            "motif": str(e)})
            continue
        for f in interp["findings"]:
            d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            d["cycle"] = {"etat": "observed",
                          "historique": [{"depuis": DISCOVERED, "evenement": "observer",
                                          "vers": transition(DISCOVERED, "observer")}]}
            findings.append(d)
        details.append({"provider": res["provider"], "etat": res["etat"],
                        "findings": len(interp["findings"]), "motif": interp["motif"]})
    verifications = None
    if verifier_oracle and findings:
        # L'oracle ne doit jamais tuer un scan : un incident est NOMMÉ dans le
        # rapport, jamais un 500 ni un findings perdu.
        try:
            verifications = _verifier_par_oracle(findings, engagement)
        except Exception as e:                      # noqa: BLE001
            verifications = {"oracle": "http_response", "erreur":
                             f"{type(e).__name__} : {str(e)[:200]}"}
    rapport = {"type": "rapport_web", "url_canonique": canonique,
               "statut_run": run["statut"], "motif_run": run["motif"],
               "providers_demandes": list(engagement.get("providers_prevus") or []),
               "providers_ecartes": ecartes, "details": details,
               "findings": findings,
               "limites_connues": [
                   "oracle http_response : rejeu réel ×N + témoin ; les findings "
                   "sans URL ou hors scope restent OBSERVED (raison nommée)",
                   "absence de correspondance ≠ absence de vulnérabilité"]}
    if verifications is not None:
        rapport["verifications"] = verifications
    if not plans:
        rapport["statut_run"] = "refuse"
        rapport["motif_run"] = "; ".join(e["motif"] for e in ecartes) or "aucun plan"
    try:
        rapport["preuve"] = PR.sceller({k: rapport[k] for k in
                                        ("type", "url_canonique", "statut_run",
                                         "providers_demandes", "details")})
    except TypeError as e:
        rapport["preuve"] = {"erreur": f"preuve_non_construite : {e}"}
    return rapport
