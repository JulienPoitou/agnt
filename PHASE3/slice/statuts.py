"""Statut par outil : les six étapes d'une exécution, réunies au même endroit.

Pourquoi ce module existe (2026-08-30) : les six faits qu'un lecteur réclame —
un outil est-il disponible, autorisé, sélectionné, exécuté, échoué, non applicable ?
étaient écrits à SIX endroits différents (`adapters._exe` pour la disponibilité,
`plan.selection` pour la sélection, la décision OPA pour l'autorisation,
`exec_.raw` pour l'exécution, la couverture pour les cibles, `e.arret` pour l'arrêt).
Résultat mesuré : quand une exécution avortait, l'écran ne pouvait plus dire lequel
de ces six faits était vrai — et un outil jamais lancé Ressemblait à un outil qui a
conclu « rien trouvé ».

Règle de construction, et c'est tout l'intérêt : AUCUN statut n'est saisi. Chacun est
DÉRIVÉ des artefacts de la mission (plan, décision, bruts, couverture, journal).
On ne peut donc pas écrire « exécuté » par optimisme : il faut la ligne de brut qui
le prouve. Inversement, un outil absent du plan ne peut jamais devenir « exécuté ».

Les sept libellés, et leur correspondance avec les six étapes demandées :

    non_disponible    l'exécutable n'est ni au cache épinglé, ni au PATH (étape 1 ratée)
    non_applicable    déclaré inapplicable à CETTE cible avant exécution (globs)
    non_selectionne   disponible et applicable, mais écarté par la priorité déclarée
    non_autorise      dans le plan, mais la décision refuse (motifs nommés)
    selectionne       dans le plan, autorisé, pas encore de sortie (état transitoire,
                      visible quand l'exécution est interrompue)
    echoue            lancé, mais sans sortie exploitable (timeout, code inattendu,
                      sortie illisible, ou exécution interrompue)
    execute           lancé, sortie conservée (avec `rien_trouve` pour distinguer
                      « 0 observation sur des cibles analysées » de « 0 cible analysée »)

Le septième libellé (`non_selectionne`) est un raffinement de « sélectionné » : le
rendre distinct, c'est refuser de confondre « l'outil n'a pas été retenu » et
« l'outil n'existe pas ». C'est la même famille d'erreur que F8, côté lecteur.
"""

from __future__ import annotations

# MCP-004 : le nom canonique du transport fourni par le cœur vient du module CORE,
# jamais d'un littéral recopié ici (un "local" écrit à la main dériverait en silence).
import transports

STATUTS = ("non_disponible", "non_applicable", "non_selectionne", "non_autorise",
           "selectionne", "echoue", "execute")


def _outils_de(plan: dict) -> list[str]:
    return [s.get("provider") for s in (plan.get("steps") or [])]


def _couverture_par(couverture: list[dict]) -> dict:
    out = {}
    for c in couverture or []:
        out[c.get("provider")] = c
    return out


def construire(registre, plan: dict, decision: dict, raw: list[dict],
               couverture: list[dict], findings_par_provider: dict,
               avorte: dict | None = None, resoudre=None, en_cours=None) -> list[dict]:
    """Ledger des six étapes, un par provider touché de près ou de loin.

    `registre`      : Registry (pour les capacités et les manifests).
    `plan`          : `plan.to_dict()` — steps + `selection` (choisis, écartés, motifs).
    `decision`      : {"allow": bool, "motifs": [...]} — la décision OPA déja consignée.
    `raw`           : exec_.raw (un élément par exécution terminée).
    `couverture`    : exec_.couverture (états par cible).
    findings_par_provider : compté à la source par le pipeline, pas recompté ici.
    `avorte`        : {"provider": id, "cause": str} quand l'exécution s'est arrêtée.
    `resoudre`      : résolveur d'exécutable — injecté pour que le test puisse juger la
                      cohérence, et pour que le ledger utilise LA MÊME règle que
                      l'exécution (une divergence afficherait « absent » à un outil lancé).
    `en_cours`      : provider dont l'exécution a commencé et n'est pas terminée. Depuis que
                      la vague est parallèle, ce fait arrive PENDANT la mission et pas
                      seulement à la fin — et il doit se lire avec le même vocabulaire, par
                      la même fonction. Un second chemin d'états (« en cours », « live »,
                      « running ») écrit à côté serait le sixième endroit où le même fait est
                      déclaré, exactement ce que ce module existe pour supprimer.
    """
    if resoudre is None:
        import adapters

        def resoudre(binaire: str):
            return adapters.resoudre_exe(binaire)

    selection = plan.get("selection") or {}
    # Deux écartements AVANT exécution, deux motifs : la cible ne s'y prête pas
    # (applicabilité), ou l'environnement ne le permet pas (conditions). Pour le lecteur
    # c'est le même statut — « non applicable » — et la raison fait la distinction.
    applicabilite = {**(selection.get("applicabilite") or {}),
                     **{k: "condition d'exécution non remplie : " + str(v)
                        for k, v in (selection.get("conditions") or {}).items()}}
    # « Non applicable » recouvre deux décisions très différentes pour un opérateur : la cible
    # ne s'y prête pas, OU l'environnement la refuse. La seconde se lève en changeant de
    # mission (`--egress`), la première non. La catégorie est donc dérivée du motif — pas d'un
    # nouveau statut : le vocabulaire des six étapes reste fermé.
    categorie_egress = {k for k, v in (selection.get("conditions") or {}).items()
                        if "egress" in str(v).lower() or "réseau" in str(v).lower()}
    bruts = {b.get("provider"): b for b in raw or []}
    couv = _couverture_par(couverture)

    # périmètre du ledger : tout ce qui a été demandé, écarté, tenté, ou qui a produit
    # une observation. Rien d'autre — le registre complet n'est pas une exécution.
    vus: list[str] = []
    for pid in _outils_de(plan):
        if pid not in vus:
            vus.append(pid)
    for pid in applicabilite:
        if pid not in vus:
            vus.append(pid)
    for cap_id, s in selection.items():
        if cap_id == "applicabilite" or not isinstance(s, dict):
            continue
        for e in s.get("ecartes") or []:
            pid = e.get("id") if isinstance(e, dict) else e
            if pid and pid not in vus:
                vus.append(pid)
    for pid in bruts:
        if pid not in vus:
            vus.append(pid)
    if avorte and avorte.get("provider") not in vus:
        vus.append(avorte["provider"])
    # Un outil écarté pour indisponibilité NE FIGURE DANS AUCUN STEP : sans cette ligne il
    # sortait du ledger en même temps que du plan, et « pourquoi ce scanner n'a rien rendu »
    # n'avait plus de réponse — l'outil n'était ni exécuté, ni écarté, ni absent. C'est
    # l'autre moitié de D10 : filtrer la sélection ne sert qu'à moitié si l'écartement ne
    # se voit pas.
    for pid in (selection.get("disponibilite") or {}):
        if pid not in vus:
            vus.append(pid)

    ledger: list[dict] = []
    for pid in sorted(vus):
        vivant = False
        try:
            prov = registre.provider(pid)
        except Exception:                              # noqa: BLE001 - le provider n'est pas dans le registre
            prov = None
        cap_id = prov.capability if prov else next(
            (s.get("capability") for s in (plan.get("steps") or [])
             if s.get("provider") == pid), "")
        transport = (getattr(prov, "transport", transports.TRANSPORT_SANDBOX_CLI) if prov
                 else transports.TRANSPORT_SANDBOX_CLI)
        binaire = (prov.commande[0] if prov and prov.commande else
                   (getattr(getattr(prov, "manifest", None), "tool", "") or
                    getattr(getattr(prov, "manifest", None), "binaire", "") or pid))
        outil = (getattr(getattr(prov, "manifest", None), "tool", "") or
                 getattr(getattr(prov, "manifest", None), "tool_id", "") or "")
        if transport != transports.TRANSPORT_SANDBOX_CLI:
            # Un provider externe n'a volontairement PAS d'exécutable local : sa
            # disponibilité de configuration est prouvée par le registre (transport
            # enregistré + binding serveur/outils), et la disponibilité réelle du
            # serveur et de l'outil distant est ensuite portée par le résultat du
            # transport. Chercher un binaire ici afficherait « non disponible » sous
            # un provider qui n'a jamais prétendu en avoir un.
            chemin_exe = "external"
            dispo = True
        else:
            chemin_exe = resoudre(binaire) if binaire else None
            if chemin_exe is None and prov is not None:
                # Deux origines pour nommer un exécutable (déclaratif : `manifest.binaire` ;
                # historique : `commande[0]`). Le ledger essaie les deux, comme
                # `adapters.exe_de` le fait au lancement : une divergence afficherait
                # « non disponible » sous un outil qui vient de tourner — et l'inverse.
                autre = getattr(getattr(prov, "manifest", None), "binaire", "") or ""
                if autre and autre != binaire:
                    binaire, chemin_exe = autre, resoudre(autre)
            dispo = chemin_exe is not None
        n = int((findings_par_provider or {}).get(pid, 0))
        c = couv.get(pid) or {}
        etats = [x.get("etat") for x in (c.get("cibles") or [])]
        analyse = sum(1 for e_ in etats if e_ == "scanned_successfully")

        brut = bruts.get(pid)
        motif_avorte = (avorte or {}).get("cause") if avorte and avorte.get("provider") == pid else None

        # ---- précédence : du plus factuel (l'outil existe-t-il ?) au plus riche ----
        if not dispo:
            # Le motif porté par le plan est repris tel quel quand il existe : c'est celui
            # qui a été écrit au moment de la DÉCISION, avec le nom d'exécutable déclaré.
            # Le recalculer ici produirait une seconde formulation du même fait — et deux
            # formulations finissent par diverger (famille F8).
            statut = "non_disponible"
            raison = str((selection.get("disponibilite") or {}).get(pid) or "").strip() or (
                f"exécutable introuvable ({binaire}) : ni au cache épinglé, ni au PATH — "
                "lancer bootstrap.sh, ou installer l'outil")
        elif motif_avorte:
            # L'exécution a été interrompue sur CE provider : c'est un échec, pas un « 0 trouvé ».
            statut, raison = "echoue", f"exécution interrompue : {motif_avorte}"
        elif pid in applicabilite:
            statut, raison = "non_applicable", str(applicabilite[pid])
        elif pid not in _outils_de(plan):
            # écarté par la sélection : le motif est celui de la capacité concernée
            motif = ""
            for cap_id_, s in selection.items():
                if cap_id_ == "applicabilite" or not isinstance(s, dict):
                    continue
                if pid in [e.get("id") for e in (s.get("ecartes") or [])
                           if isinstance(e, dict)]:
                    motif = f"écarté par la sélection de « {cap_id_} » — {s.get('motif', '')}"
                    break
            statut, raison = ("non_selectionne",
                              motif or "provider du plan absent — écarté avant l'exécution")
        elif not decision.get("allow", False):
            statut, raison = "non_autorise", (
                "décision : " + (", ".join(decision.get("motifs") or []) or "refus sans motif nommé"))
        elif brut is None and pid == en_cours:
            # Le mot « en cours » n'est pas un huitième statut : c'est `selectionne` avec la
            # raison qui dit qu'il tourne. Ajouter un statut vivant ferait deux vocabulaires de
            # l'avancement, et l'un des deux mentirait forcément sur les six étapes.
            statut, raison, vivant = "selectionne", "exécution en cours", True
        elif brut is None:
            statut, raison = "selectionne", "dans le plan et autorisé, aucune sortie conservée"
        else:
            att = ()
            mani = getattr(prov, "manifest", None)
            if mani is not None:
                att = tuple(getattr(mani, "code_succes", ()) or ())
            codes_ok = att or (0,)
            if brut.get("timeout") or brut.get("statut") == "timed_out":
                statut, raison = "echoue", ("timeout" if transport == transports.TRANSPORT_SANDBOX_CLI
                                            else "timeout provider")
            elif brut.get("statut") in ("unavailable", "invalid", "failed", "cancelled"):
                statut, raison = "echoue", (
                    f"provider {transport} : statut {brut.get('statut')} — "
                    f"{brut.get('erreur') or 'aucune sortie exploitable'}")
            elif brut.get("code_retour") not in codes_ok:
                statut, raison = "echoue", (
                    f"code retour {brut.get('code_retour')} hors {list(codes_ok)} "
                    "(codes déclarés par le manifest)")
            else:
                statut = "execute"
                if analyse == 0:
                    raison = "sortie conservée, AUCUNE cible analysée — ce n'est pas un scan propre"
                elif n == 0:
                    raison = f"{analyse} cible(s) analysée(s), 0 observation"
                else:
                    raison = f"{analyse} cible(s) analysée(s), {n} observation(s)"
        if brut is not None and statut == "non_disponible":
            # Un brut sur disque pour un outil jugé indisponible est une CONTRADICTION :
            # soit le cache a bougé pendant la mission, soit l'empreinte ne pointe pas au
            # même endroit. C'est le seul cas où la mention sert au lecteur — l'ajouter
            # partout (timeout, échec) noierait la raison sous un détail déjà dans `raw`.
            raison += (f" — ATTENTION : une sortie conservée existe pourtant "
                       f"(code {brut.get('code_retour')})")

        disponibilite = None
        if transport != transports.TRANSPORT_SANDBOX_CLI:
            disponibilite = (brut or {}).get("disponibilite") or {
                "status": "unknown",
                "reason": "aucun résultat MCP conservé",
                "checked_at": "",
            }

        entry = {
            "provider": pid,
            "capability": cap_id,
            "outil": outil,
            "binaire": binaire,
            "transport": transport,
            **({"disponibilite": disponibilite} if disponibilite is not None else {}),
            "request_id": (brut or {}).get("request_id"),
            "server_id": getattr(prov, "server_id", "") if prov else "",
            "tool": getattr(prov, "tool", "") if prov else "",
            "provider_version": getattr(prov, "provider_version", "") if prov else "",
            "server_version": getattr(prov, "server_version", "") if prov else "",
            "tool_version": getattr(prov, "tool_version", "") if prov else "",
            "protocol_version": getattr(prov, "protocol_version", "") if prov else "",
            "trust": getattr(prov, "trust", "") if prov else "",
            "disponible": dispo,
            "statut": statut,
            "raison": raison,
            "findings": n,
            "code_retour": (brut or {}).get("code_retour"),
            "timeout": bool((brut or {}).get("timeout")),
            "cibles_analysees": analyse,
            "rien_trouve": bool(statut == "execute" and analyse > 0 and n == 0),
            "en_cours": vivant,
            **({"motif_categorie": "egress_non_autorise"} if pid in categorie_egress else {}),
        }
        if statut not in STATUTS:
            raise AssertionError(f"statut hors vocabulaire fermé : {statut!r}")
        ledger.append(entry)
    return ledger


def resumer(ledger: list[dict]) -> dict:
    """Compte par statut — pour que le résumé dise « 3 exécutés, 2 non disponibles »."""
    out = {s: 0 for s in STATUTS}
    for e in ledger:
        out[e["statut"]] = out.get(e["statut"], 0) + 1
    return out


def declencheurs_escalade(ledger: list[dict], registre, tentes, plafond: int) -> list[dict]:
    """Où une capacité est restée NON COUVERTE alors que l'outil a tourné, et qui la supplée.

    Déclencheur unique et déclaré : un outil `execute` avec `cibles_analysees == 0`. C'est
    le seul cas où lancer un second outil change quelque chose pour le lecteur — l'outil
    a rendu une sortie exploitable mais n'a rien pu analyser (absence de lockfile, de
    manifest, de règles applicables). Un outil qui a analysé et rien trouvé n'est PAS un
    déclencheur : escalader là reviendrait à faire dire au nombre de findings ce que la
    couverture dit déjà.

    Un seul suppléant par capacité, dans l'ordre de priorité déclarée, et seulement s'il
    est PASSIF : la fonction ne crée aucune autorisation, elle propose des candidats que
    le plan et OPA trancheront ensuite.
    """
    tentes = set(tentes or ())
    # Import local, comme dans `construire` : ce module ne connaît `adapters` que pour la
    # disponibilité, et `adapters` regarde déjà vers ici.
    try:
        import adapters as _AD
    except Exception:                                      # noqa: BLE001
        _AD = None

    def _disponible(p) -> bool:
        # Sans `adapters` (module injoignable), ou pour un registre de test (non-plateforme),
        # on ne filtre pas la disponibilité pour permettre les tests sur mocks.
        if _AD is None or not getattr(registre, "_registre_de_la_plateforme", True):
            return True
        return bool(_AD.exe_de(p))

    out: list[dict] = []
    for e in ledger:
        if len(out) >= plafond:
            break
        if not (e.get("statut") == "execute" and e.get("cibles_analysees") == 0):
            continue
        cap = e.get("capability")
        if not cap:
            continue
        # LE DÉCLENCHEUR LUI-MÊME est exclu, structurellement : sans cette ligne, un
        # provider qui n'avait rien à analyser se voyait proposé comme son propre
        # suppléant (mesuré en test le 2026-08-30) — relancer le même outil sur la même
        # cible ne produit rien, sinon une seconde facture et un faux air de progression.
        tentes.add(e.get("provider"))
        try:
            # D10 (31/08/2026), second chemin : le suppléant doit EXISTER sur la machine,
            # pas seulement être déclaré et passif. Sans ce filtre, `checkov` (0 cible
            # analysée sur un dépôt sans IaC) se voyait suppléé par `kics` — absent. Le
            # provider était lancé, échouait au exec dans la cage, et le journal portait
            # une ligne d'exécution pour un binaire qui n'a jamais été installé. La règle
            # est donc la même ici que dans `intent.choisir_providers` : la disponibilité
            # se juge AVANT de proposer, jamais après avoir lancé.
            candidats = [p.id for p in registre.capability(cap).providers
                         if p.id not in tentes and p.risque == "PASSIVE"
                         and _disponible(p)]
        except Exception:                                  # noqa: BLE001 - capacité inconnue
            continue
        if not candidats:
            continue
        out.append({"provider": e["provider"], "capacite": cap,
                    "motif": "outil lancé sans aucune cible analysée",
                    "suppleant": candidats[0]})
        tentes.add(candidats[0])
    return out
