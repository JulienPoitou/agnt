"""Pipeline de bout en bout — le vertical slice.

    phrase → capacités → providers → plan typé → OPA
           → sandbox → raw results → couverture
           → findings normalisés → identités canoniques
           → clustering v0 → rapport

Un seul processus Python, aucun service séparé. Le runner est déterministe : à requête
et registre identiques, il produit le même plan et la même empreinte (critère n°10).
"""

from __future__ import annotations

import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import adapters
import cible as CIB
import transports
import clusterer
import garde_chemin as GC
import mission as MS
import profils
import run as RUN
import findings as F
import intent
import plan as P
import policy as PO
from registre import Registry
import statuts as STAT
import conditions as COND
from provider_contract import Target
from sandbox import CACHE_BIN, CACHE_DB, CACHE_REGLES, Sandbox

RACINE = Path(__file__).resolve().parent.parent     # PHASE3/

# Moteur d'intention : "deterministe" (référence) ou "llm".
# Le LLM ne remplace QUE le matching — jamais le contrat, ni le registre, ni OPA.
# Escalade bornée (2026-08-30) : au plus MAX_ESCALADE fournisseurs suppléants, dans une
# seule vague de plus. Le plafond n'est pas un réglage de performance : sans lui, une
# couverture insuffisante déclencherait une chaîne d'essais dont personne ne peut dire
# quand elle s'arrête — exactement le reproche fait aux agents « autonomes ».
MAX_ESCALADE = 3

# Outils menés de front dans une vague. 4 par défaut, et la borne est un CHOIX ASSUMÉ, pas une
# mesure de gain : les namespaces bwrap sont indépendants (aucun état partagé dans `Sandbox`,
# qui est figé) et les sorties sont nommées par provider, donc l'exactitude ne dépend pas de la
# valeur. Ce qui dépend d'elle, c'est la pression sur le CPU et sur les bases locales — et ça,
# cette machine ne peut pas le mesurer (un seul outil hors réseau installable, `bwrap` refusant
# les user namespaces). Le gagnage de temps réel est donc NON ÉVALUÉ ici, l'invariance des
# artefacts entre 1 et 4 est mesurée (`test_vague_parallele.py`).
def outils_par_vague() -> int:
    brute = os.environ.get("AGNT_VAGUE_PARALLELE", "4")
    try:
        n = int(brute)
    except ValueError:
        # Une valeur illisible n'est pas une autorisation de tout lancer : on retombe sur 1,
        # le comportement historique séquentiel, et on le dit dans le journal de mission.
        return 1
    return max(1, min(n, 8))

# Moteur d'intention PAR DÉFAUT d'une exécution. `executer()` les accepte désormais en
# paramètres (`moteur_intent`, `fournisseur_llm`) : un appelant qui les fournit ne dépend
# plus de ces globales, et deux missions peuvent choisir deux moteurs différents dans le
# même processus sans se marcher dessus. Ces deux noms restent lisibles comme DÉFAUT de
# dernier recours (compatibilité ascendante : les tests et appelants historiques qui les
# posaient continuent de fonctionner), mais la bibliothèque ne les MUTE plus — c'est le
# changement qui compte pour le multi-mission, pas l'existence de la constante.
MOTEUR_INTENT = "deterministe"
FOURNISSEUR_LLM = None

# Confiances de cible admises : exactement les valeurs que `policy.rego` compare à
# `input.cible.confiance`. La liste vit ici, et non dans un drapeau CLI, parce que
# c'est la bibliothèque qui applique la décision — toute entrée d'appel (CLI, test,
# appelant tiers) passe par ce contrôle.
CONFIANCES = ("controlled", "untrusted")


class PipelineError(Exception):
    pass


@dataclass
class Execution:
    plan: dict
    decision: dict
    intent: dict = field(default_factory=dict)
    arret: str = ""
    run_id: str = ""
    profil: str = ""
    contexte: dict = field(default_factory=dict)
    chemin: dict = field(default_factory=dict)
    raw: list[dict] = field(default_factory=list)
    couverture: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    clusters: dict = field(default_factory=dict)
    rapport: dict = field(default_factory=dict)
    result_digest: str = ""
    # Escalades de vague 2 : déclencheur, décision, exécution. Vide = aucun déclencheur.
    escalades: list = field(default_factory=list)
    # Ledger des six étapes par outil (disponible/autorisé/sélectionné/exécuté/
    # échoué/non applicable) — dérivé, jamais saisi. Vide = exécution antérieure.
    statuts: list = field(default_factory=list)
    # Dossier de mission (étape 2) : identifiant du journal append-only qui a
    # tracé cette exécution. Chaîne vide = exécution antérieure à l'étape 2.
    mission: str = ""
    # État de la garde d'export pour cette mission (LOT 3) : qui a demandé, si c'est accordé,
    # sur quel profil. Present même quand c'est « coupé » — un défaut fermé doit se lire.
    egress: dict = field(default_factory=dict)
    # Nombre d'outils menés de front dans une vague (0 = suite du profil, aujourd'hui 4).
    vague_parallele: int = 0
    # Répertoire de travail de CETTE exécution (raw_*/brut_* de la vague). Par mission,
    # plus par processus : deux missions concurrentes ne se réécrivent pas. Chaîne vide
    # = exécution arrêtée avant l'étape d'exécution (intent, policy, conditions…).
    sortie: str = ""


def _sortie_mission(miss) -> Path:
    """Répertoire de travail de la mission : `raw_*`/`brut_*` d'une vague, par mission.

    Avant ce lot, la sortie était un répertoire GLOBAL (`PHASE3/run`) vidé au début de
    CHAQUE exécution : deux missions concurrentes se réécrivaient l'une l'autre, et le
    simple fait d'exécuter une mission effaçait les preuves de la précédente. Le dossier
    de mission (append-only, déjà unique) devient la frontière d'isolation : on crée un
    sous-répertoire neuf, on ne vide jamais un répertoire partagé.

    Ce répertoire est BINDÉ dans le sandbox : on le crée avant, et on ne le supprime
    jamais ensuite (supprimer un répertoire déjà bindé casserait le montage).
    """
    sortie = miss.chemin / "run"
    sortie.mkdir(parents=True, exist_ok=True)
    return sortie


def _racines_de(cible: Path) -> tuple:
    """La cible sous les formes qu'un outil peut employer pour la nommer.

    Le montage de l'isolateur, la cible absolue, et — depuis le 2026-08-30 — la cible
    nommée relativement au dépôt. Occurrence mesurée sur `testrepo_iac` : checkov rend
    « /PHASE3/testrepo_iac/k8s.yaml » (chemin construit depuis le répertoire du run)
    là où kics, trivy et semgrep rendent « k8s.yaml » ; 20 findings de la fixture
    ne pouvaient donc rencontrer aucun autre outil sur ce fichier. Aucune devinette :
    uniquement des racines CONNUES, jamais une ressource filesystem.
    """
    formes = [Sandbox.M_SCAN, str(cible)]
    try:
        formes.append(str(Path(cible).resolve().relative_to(RACINE.parent)))
    except (ValueError, OSError):
        pass                                        # cible hors du dépôt : rien à ajouter
    return tuple(f for f in dict.fromkeys(x for x in formes if x))


def _consigner_arret(miss, motif: str, exc: BaseException) -> None:
    """Consigne la CAUSE d'un arrêt déclenché par une exception, sans jamais l'avaler.

    Un dossier de mission qui s'arrête net n'est pas une trace : « rien ne s'est passé ici »
    et « voici pourquoi ça s'est arrêté » se lisaient de la même façon. L'appelant relance
    toujours l'exception après cet appel — ici on écrit uniquement ce qui manquait au
    journal. Et l'écriture du journal ne doit jamais, elle non plus, transformer une panne
    d'outil en panne de mission : si le disque refuse la ligne, on garde l'exception d'origine.
    """
    try:
        MS.consigner(miss, "arret", motif=motif, erreur=f"{type(exc).__name__}: {exc}")
    except Exception:                                    # journal secondaire, jamais bloquant
        pass


def _ledger(miss, registre, plan_dict, decision_dict, raw, couverture,
            findings_par: dict, avorte: dict | None = None, en_cours=None) -> list:
    """Ledger des six étapes par outil, consigné au journal AUSSI TÔT que possible.

    Consisté à chaque sortie — y compris les sorties interrompues : un refus de policy
    ou une garde de chemin qui avorte doit laisser le lecteur savoir ce qui était
    disponible et autorisé, sinon « rien n'a tourné » et « tout a tourné proprement »
    se ressemblent sur l'écran.
    """
    st = STAT.construire(registre, plan_dict or {}, decision_dict or {},
                        raw, couverture, findings_par, avorte=avorte, en_cours=en_cours)
    MS.consigner(miss, "statuts", resume=STAT.resumer(st), outils=st,
                 **({"en_cours": en_cours} if en_cours else {}))
    return st


@dataclass
class _ContexteVague:
    """Ce qu'une vague touche dans la mission. Un seul objet, construit une fois.

    Listes et dicts MUTABLES volontairement : la vague 2 (escalade) doit écrire dans les mêmes
    `exec_.raw`, `trouves` et `tous_findings` que la vague 1 — deux copies produiraient deux
    moitiés d'artefact, et le rapport ne saurait plus lequel est complet.
    """
    miss: object
    registre: object
    exec_: object
    sbx: object
    cible: Path
    sortie: Path
    # Le contexte d'exécution (versions d'outils, empreintes) : la vague en a besoin pour
    # `source.version_outil`. Omis à l'extraction du corps, il donnait un `NameError` sur le
    # PREMIER finding enrichi — trouvé par `test_vague_parallele.py`, invisible tant
    # qu'aucun outil ne rendait de finding. Un nom libre dans une fonction extraite est
    # exactement le défaut que ce lot devait produire, et c'est le test qui l'a eu.
    ctx: object
    trouves: dict
    tous_findings: list
    domaines: dict
    binaires: dict
    # Factories injectées par test ou par un futur runtime de mission. Elles sont
    # indexées par provider et non globales : une mission ne partage pas une session
    # MCP, des credentials ou un cache mutable avec une autre.
    transport_factories: dict = field(default_factory=dict)


def _vague(steps_, V, plan_dict, decision_dict, horodatage, vague):
    """Une vague d'exécution — la vague 1 et l'escalade partagent CE CORPS, à la racine du module.

    Extraire la boucle en fonction (plutôt que copier un second cycle pour la vague 2) est ce
    qui garantit qu'une exécution escaladée passe par TOUTES les gardes de l'exécution normale :
    brut conservé sur disque, couverture, fingerprints sur chemins normalisés, enrichissement,
    journal par provider, ledger partiel si elle avorte. Une seconde boucle « simplifiée » est
    exactement le chemin de côté qui finit par produire des artefacts non comparables.

    Le contexte de mission est passé (`V`), pas capturé : c'est ce qui rend CE corps
    exécutable par un test sans `opa` ni `bwrap` — la vague se pilote à vide sur des doubles
    de sandbox, et ses artefacts se comparent. Un corps enfermé dans une closure ne se prouve
    qu'en rejouant la mission entière, c'est-à-dire qu'il ne se prouve pas sur une machine où
    la politique est injouable.

    Depuis LOT 3, les outils d'une même vague peuvent tourner de front. Trois choses sont
    gardées, dans cet ordre, et c'est tout l'intérêt du morceau :

      1. LE MÊME CORPS par outil — la parallelisation porte sur l'ordonnancement, pas sur les
         gardes : un outil lancé en parallèle écrit son brut, sa couverture, ses findings et sa
         ligne de journal exactement comme s'il tournait seul.
      2. DES ARTEFACTS DÉTERMINISTES — les résultats sont collectés puis MERGÉS dans l'ordre du
         plan, jamais dans l'ordre d'achèvement. Sans ça, deux exécutions du même plan
         produiraient deux `findings.json` différents (ordre des findings, ordre de `raw`, ordre
         des lignes du journal) et l'empreinte de résultat ne serait plus une empreinte de
         résultat mais une empreinte d'horloge.
      3. UN SEUL POINT D'ARRÊT — la première exception (au sens de l'ordre du plan) interrompt la
         vague : les outils déjà partis vont à leur terme, ceux qui n'ont pas démarré sont
         abandonnés. Rien ne tourne « à moitié » et rien ne tourne après une décision de
         sécurité négative.

    Le ledger est consigné À CHAQUE DÉPART d'outil, pas seulement à la fin : c'est la source des
    états vivants de la console, et il est produit par la même fonction `statuts.construire` que
    l'état final — pas par une seconde mécanique d'affichage.
    """
    miss, registre, exec_, sbx = V.miss, V.registre, V.exec_, V.sbx
    cible, sortie = V.cible, V.sortie
    trouves, tous_findings = V.trouves, V.tous_findings
    domaines_du_provider = V.domaines
    binaire_de_provider = V.binaires
    ctx = V.ctx
    resultats: dict[str, tuple] = {}
    erreurs: dict[str, BaseException] = {}
    verrou = threading.Lock()
    avorter = threading.Event()

    def _vivant(pid: str) -> None:
        with verrou:
            _ledger(miss, registre, plan_dict, decision_dict, list(exec_.raw),
                    list(exec_.couverture), dict(trouves), en_cours=pid)

    def _un(step) -> None:
        prov = registre.provider(step.provider)
        if avorter.is_set():
            return                      # vague déjà condamnée : on ne lance pas un autre outil
        _vivant(prov.id)
        try:
            # Une cible typée est construite une fois par l'orchestrateur, puis remise
            # au backend. Le transport ne reçoit jamais un chemin pour décider lui-même
            # de ce qu'est la cible ; il ne reçoit que cette donnée validée.
            types_cible = tuple(prov.target_types or ())
            if "repository" in types_cible:
                kind = "repository"
            elif "filesystem" in types_cible:
                kind = "filesystem"
            else:
                # Cette façade reçoit aujourd'hui une Path locale. Ne pas la
                # convertir en faux URL/hôte/image : ces cibles attendent le
                # descripteur canonique CORE et ne sont pas téléchargées ou montées
                # implicitement dans Sandbox.
                raise PipelineError(
                    f"{prov.id}: cible {types_cible} non supportée par la façade Path "
                    "— descripteur Cible CORE requis")
            cible_typed = Target(kind, str(cible))
            brut = adapters.executer(
                prov, sbx, target=cible_typed,
                transport_factory=V.transport_factories.get(prov.id),
                cancel_event=avorter)
        except Exception as exc:
            # Un échec d'ADAPTATION (isolateur inutilisable : montages absents, bwrap
            # manquant) n'est pas une ligne de couverture : `verifie()` refuse avant tout
            # Popen, et la mission avorte — rien ne doit tourner à moitié. Ce qui manquait,
            # c'est la trace du motif, nommée par provider. La cause reste l'affaire de
            # l'appelant (l'exception remonte telle quelle), le journal, lui, doit la dire.
            with verrou:
                erreurs[prov.id] = exc
            avorter.set()
            return
        with verrou:
            resultats[prov.id] = (prov, brut)

    # L'ordonnanceur est la seule partie qui change selon le plafond ; le travail d'un
    # outil est le même appel dans les deux cas. Deux chemins d'exécution d'un même fait
    # est le début d'une divergence entre ce qui tourne et ce qui est consigné.
    plafond = outils_par_vague()
    if len(steps_) <= 1 or plafond <= 1:
        for step in steps_:
            _un(step)
    else:
        with ThreadPoolExecutor(max_workers=min(plafond, len(steps_))) as pool:
            list(pool.map(_un, list(steps_)))

    # ---- consolidation, dans l'ordre du plan (voir la règle 2 ci-dessus)
    for step in steps_:
        if step.provider not in resultats:
            continue
        prov, brut = resultats[step.provider]
        # Le RAW est conservé TEL QUEL, sans retraitement — invariant que la ligne « PR #1 »
        # nommait dans son propre bloc et qui est repris ici au merge (2026-08-31) : le
        # masquage, lui, ne se joue pas à l'écriture du brut mais à l'export (`analyser.py`,
        # `raw_*` + `brut_*` examinés avant copie). Un brut retraité ici ne prouverait plus
        # ce que l'outil a écrit.
        (sortie / f"raw_{prov.id}.json").write_text(
            json.dumps(brut.donnees, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8")
        # La sortie brute est conservée À CÔTÉ du JSON re-construit, jamais à sa place :
        # le JSON dit ce que le cœur a COMPRIS, le brut dit ce que l'outil a ÉCRIT. Les
        # deux doivent pouvoir être comparés des mois plus tard (demande explicite de la
        # commande du 2026-08-30, « conserver systématiquement la sortie brute »).
        nom_brut = adapters.conserver_brut(sbx, sortie, brut, prov.id)
        exec_.raw.append({
            "provider": prov.id,
            "fichier": f"raw_{prov.id}.json",
            "brut": nom_brut,
            "code_retour": brut.code_retour,
            "timeout": brut.timeout,
            "vague": vague,
            # Contrat provider : les consommateurs structurés n'ont pas à parser une
            # erreur MCP dans stderr. Ces champs restent valides pour les providers
            # locaux (statut succeeded par compatibilité).
            "statut": getattr(brut, "statut", "succeeded"),
            "erreur": getattr(brut, "erreur", ""),
            "transport": getattr(brut, "transport", transports.TRANSPORT_SANDBOX_CLI),
            "correlation_id": getattr(brut, "correlation_id", ""),
            "request_id": getattr(brut, "request_id", ""),
            "identite_provider": getattr(brut, "identite_provider", {}) or {},
            **({"disponibilite": brut.disponibilite}
               if getattr(brut, "disponibilite", None) else {}),
        })
        exec_.couverture.append(brut.couverture.to_dict())

        # Chemins relativisés aux racines CONNUES (montage isolateur + cible sous
        # toutes ses formes) AVANT calcul des fingerprints : identité indépendante de
        # la machine (2026-08-28), élargie aux orthographes du dépôt (2026-08-30).
        norm = F.normaliser(prov.id, brut.donnees, mani=prov.manifest,
                            racines=_racines_de(cible))
        # Trois champs qu'un finding ne peut pas connaître seul, dérivés ici parce que
        # c'est le pipeline qui détient le registre et le contexte :
        #   · `categorie` = premier domaine DÉCLARÉ de la capacité (pas un dictionnaire
        #     d'outils entretenu à la main) ;
        #   · `horodatage` = l'heure du plan de la vague, pas une invention par finding ;
        #   · `version_outil` = la version LUE au démarrage, celle qui a produit ces octets.
        # Un outil muet sur un champ le laisse absent : `vue_unifiee` le déclare dans
        # `absents`, jamais le normaliseur qui le remplit.
        for f_ in norm:
            f_.source["categorie"] = domaines_du_provider.get(prov.id)
            f_.source["horodatage"] = horodatage
            # Un binaire local obtient sa version du contexte capturé ; un provider
            # externe n'a pas de binaire local et porte la version déclarée/rapportée
            # par son binding. L'absence reste None : elle n'est jamais devinée.
            f_.source["version_outil"] = (
                (getattr(brut, "identite_provider", {}) or {}).get("tool_version")
                or (ctx.outils or {}).get(binaire_de_provider.get(prov.id, ""))
                or getattr(prov, "tool_version", "")
                or None)
            f_.source["vague"] = vague
        tous_findings.extend(norm)
        trouves[prov.id] = len(norm)
        MS.consigner(miss, "execution", provider=prov.id, vague=vague,
                     code_retour=brut.code_retour, timeout=brut.timeout,
                     statut=getattr(brut, "statut", "succeeded"),
                     transport=getattr(brut, "transport", transports.TRANSPORT_SANDBOX_CLI),
                     correlation_id=getattr(brut, "correlation_id", ""),
                     request_id=getattr(brut, "request_id", ""),
                     erreur=getattr(brut, "erreur", ""),
                     disponibilite=getattr(brut, "disponibilite", {}) or {},
                     findings=len(norm))

    if erreurs:
        # Le premier fautif AU SENS DU PLAN, pas au sens de l'horloge : le motif consigné
        # et l'exception remontée doivent être les mêmes d'une exécution à l'autre.
        coupable = next((s.provider for s in steps_ if s.provider in erreurs), None)
        exc = erreurs[coupable]
        _consigner_arret(miss, f"execution_{coupable}", exc)
        _ledger(miss, registre, plan_dict, decision_dict, exec_.raw, exec_.couverture,
                trouves, avorte={"provider": coupable, "cause": str(exc)})
        raise exc
    # Fin de vague : l'état vivant laisse place à l'état complet, par la même fonction.
    _ledger(miss, registre, plan_dict, decision_dict, exec_.raw, exec_.couverture, trouves)


def executer(requete: str, cible, cible_autorisee: bool = False,
             confiance_cible: str = "controlled",
             avec_internes: bool = False, escalade: bool = True,
             egress: bool | None = None,
             moteur_intent: str | None = None,
             fournisseur_llm: object | None = None, *, registre=None,
             policy_engine=None, transport_factories: dict | None = None) -> Execution:
    """Exécute une mission de bout en bout.

    `egress` : l'autorisation de sortir (réseau) pour CETTE mission.
    `None` = on s'en tient au profil (donc coupé, aujourd'hui). `True` n'est pas un réglage
    de confort : c'est une DÉLÉGATION, et elle est traitée comme telle — le profil effectif
    de la mission est reconstruit avec (`dataclasses.replace`), transmis à OPA pour que la
    décision porte la même information que l'exécution, consigné au journal, et inscrit dans
    l'empreinte de contexte par `sandbox.limites_appliquees()`. Un `True` silencieux aurait
    produit des findings dont personne ne peut dire s'ils viennent d'une cage ouverte.

    `moteur_intent` / `fournisseur_llm` : le moteur d'intention de CETTE mission. Ces
    paramètres rendent le choix d'exécution EXPLICITE et local à l'appel, au lieu de
    passer par des globales de module mutables (`MOTEUR_INTENT`, `FOURNISSEUR_LLM`) que
    deux missions concurrentes se disputeraient. `None` = repli sur les globales
    (comportement historique, conservé pour compatibilité).

    `cible` : accepte un `Path` (appel historique), une chaîne (chemin local ou URL),
    ou une `cible.Cible` déjà construite. Elle est normalisée UNE FOIS à l'entrée
    (`cible.normaliser`) ; une cible non locale est représentée, jamais convertie en
    chemin ni exécutée en sous-processus local.

    ``registre``, ``policy_engine`` et ``transport_factories`` sont des points d'injection
    de test/runtime compatibles avec le CORE ; en production ils restent absents et le
    pipeline construit les objets canoniques. Ils ne constituent pas une deuxième autorité.
    """
    if confiance_cible not in CONFIANCES:
        # Pas de repli : une valeur non reconnue vaudrait «controlled» par accident,
        # et désarmerait silencieusement la garde mémoire de la policy.
        raise PipelineError(
            f"confiance de cible inconnue : {confiance_cible!r} · admises : "
            f"{' | '.join(CONFIANCES)}")
    # Le moteur d'intention est résolu UNE FOIS, localement : c'est le choix de CETTE
    # mission, pas un état que l'appelant aurait dû poser sur le module.
    moteur_intent = MOTEUR_INTENT if moteur_intent is None else moteur_intent
    fournisseur_llm = FOURNISSEUR_LLM if fournisseur_llm is None else fournisseur_llm
    registre = Registry() if registre is None else registre

    # ---------------------------------------------------------------- 0. cible
    # Normalisation UNIQUE de frontière (2026-08-30) : un Path historique, une chaîne
    # (chemin ou URL), ou un descripteur déjà construit deviennent UNE Cible structurée.
    # En aval, le cœur ne reconvertit plus jamais la cible en Path : il lit le
    # descripteur (`cib`) et, quand elle existe, sa forme locale (`chemin_cible`).
    # Une URL n'est donc jamais convertie en chemin, jamais montée, jamais exécutée
    # en sous-processus local.
    cib = CIB.normaliser(cible)
    chemin_cible = cib.chemin_local          # Path | None
    reference_cible = cib.reference

    # ---------------------------------------------------------------- 0b. mission
    # Le dossier append-only s'ouvre AVANT toute décision : un arrêt (intent non
    # résolu, policy) doit être tracé autant qu'une exécution complète.
    miss = MS.ouvrir(requete, P.canonicaliser(requete), reference_cible,
                     cible_descr=cib.to_dict())
    # La confiance APPLIQUÉE est consignée immédiatement, avant la policy : « qu'est-ce
    # qu'on a cru de cette cible ? » doit se relire dans le dossier de mission même si
    # la policy refuse ensuite — et même si OPA est indisponible.
    MS.consigner(miss, "confiance", confiance_cible=confiance_cible,
                 cible_autorisee=cible_autorisee, profil=profils.actif().nom)

    # ---- 0b. export réseau : une délégation, pas un défaut de lecture du profil
    import dataclasses as _dc
    profil_eff = profils.actif()
    egress_accorde = bool(profil_eff.reseau_autorise if egress is None else egress)
    egress_info = {"demande": ("profil" if egress is None else "mission"),
                   "autorise": egress_accorde,
                   "profil": profil_eff.nom}
    if egress_accorde != bool(profil_eff.reseau_autorise):
        profil_eff = _dc.replace(
            profil_eff, reseau_autorise=egress_accorde,
            commentaire=(f"{profil_eff.commentaire} · " if profil_eff.commentaire else "")
            + "délégation réseau accordée pour cette mission")
        egress_info["delegation"] = True
    MS.consigner(miss, "egress", **egress_info)
    # Le sens de la garde ne se négocie pas : `egress: false` sur une mission dont le profil
    # autorise déjà la sortie ne peut pas AGIR (il ne reste rien à couper ici, la cage est
    # l'autorité), mais il ne doit pas non plus rouvrir ce que le profil a fermé.
    egress_accorde = bool(profil_eff.reseau_autorise)

    # ---------------------------------------------------------------- 1. intention
    # Les garde-fous déterministes s'appliquent dans les DEUX modes : une demande
    # explicitement interdite n'est jamais soumise à un modèle.
    if moteur_intent == "llm" and fournisseur_llm is not None:
        import intent_llm
        it = intent_llm.garde_fous(requete, registre)
        if it is None:
            it = intent_llm.inferer(requete, registre, fournisseur_llm)
    else:
        it = intent.inferer(requete, registre, avec_internes=avec_internes)

    # La DÉCISION d'intention est consignée pour tous les états — y compris les arrêts :
    # « pourquoi cette capacité » se relit dans le journal (motif du matching), pas en
    # rouvrant plan.json. Un journal qui s'arrête à « intent_rejected » ne dit pas QUOI
    # a été compris ni pourquoi. Les `motifs` sont les mots-clés qui ont matché, jamais
    # des noms d'outil (le registre ne les expose pas au moteur d'intention).
    MS.consigner(miss, "intention", statut=it.statut,
                 capabilities=list(it.capabilities),
                 motifs=dict(it.motifs), moteur=it.moteur,
                 question=it.question, motif=it.motif)

    # Un intent non résolu n'exécute RIEN. Ni plan, ni policy, ni outil.
    # C'est testé : c'est la différence entre « il manque une information » et
    # « la demande est refusée », et aucune des deux ne doit produire d'exécution.
    if not it.executable():
        MS.consigner(miss, "arret", motif=f"intent_{it.statut}")
        return Execution(plan={}, decision={"allow": False, "motifs": [f"intent_{it.statut}"]},
                         intent=it.to_dict(), arret=it.statut, mission=miss.id)

    # --------------------------------------------- 1bis. disponibilité (D10, 31/08/2026)
    # Un slot de fan-out occupé par un outil ABSENT est pire qu'un slot vide : il est
    # invisible (aucune couverture ne le mentionne), il évinçait un outil présent, et il
    # se lisait comme un choix de plan. Mesuré : `gitleaks`, rang 100, absent depuis la
    # réinitialisation du sandbox, gardait sa place et sortait `trufflehog3` (rang 400,
    # installé) du plan — sans jamais tourner.
    #
    # La décision est prise ICI et pas dans `intent.choisir_providers` : c'est le pipeline
    # qui sait ce qu'est une machine, le sélectionneur ne connaît que le registre. Le
    # prédicat passe par `adapters.exe_de`, c'est-à-dire LA MÊME fonction qui résout
    # l'exécutable au moment de lancer et qui alimente le ledger — trois réponses
    # différentes à « l'outil est-il là ? » est exactement la famille de défauts F8.
    #
    # ── ORDRE RETENU, arbitré le 31/08/2026 ──────────────────────────────────────────
    #     registre → disponibilité → applicabilité → conditions → POLICY → exécution
    #
    # L'alternative était de laisser la policy voir les outils absents, et de ne
    # constater leur absence qu'à l'exécution. Trois raisons de ne pas le faire :
    #
    #   1. FAUSSE ATTRIBUTION (la pire). Un outil absent passé en policy se voit
    #      AUTORISÉ ou REFUSÉ — et le ledger le range alors sous « non_autorise » alors
    #      que la cause réelle est « le binaire n'est pas sur cette machine ». Deux
    #      endroits qui racontent des vérités différentes : c'est F8, et sur un écran de
    #      sécurité c'est une réparation entreprise sur la mauvaise cause.
    #   2. LA POLICY AUTORISE UN PLAN FAISABLE, pas une liste de vœux. Lui soumettre
    #      « gitleaks » quand gitleaks n'existe pas, c'est lui demander de se prononcer
    #      sur quelque chose qui n'arrivera jamais — et rendre la décision inexploitable
    #      à la relecture.
    #   3. FERMETURE PAR DÉFAUT. Plan vide → rien n'est exécuté. C'est strictement plus
    #      sûr qu'autoriser puis échouer au lancement.
    #
    # Contre-partie assumée : le plan dépend de la machine (comme il dépendait déjà de
    # la base de vulnérabilités via `conditions`). La portabilité du `plan_id` entre deux
    # machines n'est donc pas une propriété de ce système, et ne l'a jamais été.
    #
    # Et l'invariant qui n'est PAS affecté : la disponibilité est consignée pour TOUS les
    # providers du registre (`exclus_dispo` ci-dessous), jamais seulement pour ceux qui
    # passent le filtre. Un refus de politique n'efface donc pas « qui était disponible »
    # du journal — c'est ce que vérifie `test_qualite_plateforme` cas 16quater.
    import adapters as AD

    # MCP-004 : la disponibilité ne se décide PAS de la même façon selon le transport.
    # Un provider `sandbox_cli` est disponible si son exécutable est résolvable sur cette
    # machine. Un provider EXTERNE n'a pas d'exécutable par contrat : chercher un binaire
    # ici l'écarterait systématiquement, et l'absence d'un provider externe deviendrait
    # une absence INEXPLIQUÉE dans la mission. Sa disponibilité de configuration est son
    # transport enregistré ; la disponibilité RÉELLE du serveur et de l'outil distants est
    # portée ensuite par le résultat du transport (`unavailable`, `timed_out`…), jamais
    # devinée avant l'appel.
    def _disponibilite(prov):
        transport = getattr(prov, "transport", None) or transports.TRANSPORT_SANDBOX_CLI
        if transport != transports.TRANSPORT_SANDBOX_CLI:
            return f"transport {transport!r} enregistré" if transports.fournit(transport) else None
        return AD.exe_de(prov)

    dispo = {p.id: _disponibilite(p) for p in registre.providers()}

    def _motif_indispo(prov):
        transport = getattr(prov, "transport", None) or transports.TRANSPORT_SANDBOX_CLI
        if transport != transports.TRANSPORT_SANDBOX_CLI:
            return (f"transport {transport!r} non enregistré : le provider externe n'est "
                    "pas exécutable tant que son transport n'a pas été enregistré. "
                    "Aucune analyse n'a été faite par cet outil, ce n'est pas "
                    "« rien trouvé ».")
        return (f"exécutable introuvable ({AD.binaire_de(prov)}) : ni au cache épinglé, ni "
                "au PATH — l'outil n'est pas sur cette machine (lancer bootstrap.sh). "
                "Aucune analyse n'a été faite par cet outil, ce n'est pas « rien trouvé ».")

    exclus_dispo = {p.id: _motif_indispo(p)
                    for p in registre.providers() if dispo.get(p.id) is None}
    provs = intent.choisir_providers(
        it, registre, disponible=lambda p: dispo.get(p.id) is not None)
    if exclus_dispo:
        MS.consigner(miss, "disponibilite",
                     ecartes={k: v for k, v in exclus_dispo.items()})

    # --------------------------------------------- 1b. applicabilité (étape 3)
    # Filtrage DÉTERMINISTE et déclaratif, AVANT le plan : un provider dont les
    # target_types ne couvrent pas le type de la cible — ou dont les globs déclarés
    # ne correspondent à aucun fichier local — est écarté avec motif tracé. Sans
    # déclaration, le provider reste éligible (pas de devinette). C'est ICI qu'une
    # cible non locale (url) écarte tous les providers locaux : elle ne descend
    # jamais vers un sous-processus sandboxé.
    provs, exclus = P.filtrer_applicabilite(provs, registre, cib)
    if exclus:
        MS.consigner(miss, "applicabilite",
                     ecartes={k: v for k, v in exclus.items()})
    # Conditions d'exécution (2026-08-30) : un outil qui exige le réseau, ou une base de
    # vulnérabilités absente, est écarté ICI plutôt que lancé pour rendre un résultat vide
    # en code 0. Sans cette ligne, « 0 vulnérabilité » se lisait comme une conclusion alors
    # que l'outil n'avait rien pu charger — la cage coupe le réseau (`--unshare-net`).
    provs, exclus_cond = COND.filtrer(provs, registre,
                                      egress=egress_accorde,
                                      racine_db=CACHE_DB)
    if exclus_cond:
        MS.consigner(miss, "conditions", ecartes=dict(exclus_cond))
    if not provs and not exclus:
        # Rien d'exécutable, et ce n'est PAS une conclusion de sécurité.
        # Les trois causes sont nommées, parce qu'elles ne se réparent pas du même geste :
        # une base absente se lève avec bootstrap.sh, une cage fermée avec `--egress`, un
        # binaire manquant avec une installation. Les fondre dans « aucune exécution
        # possible » ferait réparer la mauvaise chose.
        causes = []
        if exclus_cond:
            causes.append("conditions d'exécution non remplies (réseau coupé ou base absente)")
        if exclus_dispo:
            causes.append("aucun outil disponible sur cette machine")
        # Le libellé de tête est conservé MOT POUR MOT : c'est un contrat de texte, pas
        # une coquetterie — un opérateur (et une batterie de tests) cherchent cette
        # phrase pour distinguer « la mission s'est arrêtée proprement, motif nommé »
        # d'une exception nue. Les causes, elles, s'ajoutent derrière.
        refus = {"allow": False,
                 "motifs": ["aucun outil exécutable dans ces conditions : "
                            + " ; ".join(causes or ["cause non nommée"])]}
        MS.consigner(miss, "arret", motif="conditions" if exclus_cond else "disponibilite",
                     ecartes={**{k: v for k, v in exclus_cond.items()},
                              **{k: v for k, v in exclus_dispo.items()}})
        st = _ledger(miss, registre,
                     {"steps": [], "selection": {"conditions": dict(exclus_cond),
                                                 "disponibilite": dict(exclus_dispo)}}, refus,
                     [], [], {})
        return Execution(plan={}, decision=refus, intent=it.to_dict(),
                         arret="conditions", mission=miss.id, statuts=st)
    if not provs:
        # Tous les providers sont inapplicables à cette cible : ce n'est pas un
        # échec, c'est une réponse honnête — rien à exécuter ici.
        MS.consigner(miss, "arret", motif="applicabilite", ecartes=exclus)
        refus = {"allow": False, "motifs": ["aucun provider applicable à cette cible"]}
        # Le ledger passe AVANT le retour : « aucun outil applicable » se lit mieux avec
        # la liste des outils écartés et leur motif qu'avec un arret sec.
        st = _ledger(miss, registre, {"steps": [], "selection": {
                          "applicabilite": dict(exclus), "conditions": dict(exclus_cond),
                          "disponibilite": dict(exclus_dispo)}},
                     refus, [], [], {})
        return Execution(plan={}, decision=refus,
                         intent=it.to_dict(), arret="applicabilite", mission=miss.id,
                         statuts=st)

    # ---------------------------------------------------------------- 2. plan typé
    plan = P.construire(requete, reference_cible, provs, registre, it.moteur,
                        exclus_applicabilite=exclus, exclus_conditions=exclus_cond,
                        exclus_disponibilite=exclus_dispo,
                        cible_descr=cib.to_dict())
    # La SÉLECTION est consignée avec le plan : « pourquoi ce provider et pas l'autre »
    # se lit dans le journal (choisis, écartés, motif), pas seulement dans plan.json. Le
    # motif vient de `plan.construire` — priorité déclarée, fan_out, ou choix imposé — et
    # c'est exactement la trace que le futur UI consommera pour expliquer une étape.
    # (Réalignement : `exclus_disponibilite` — dimension de disponibilité de PR #2 —
    # et `cible_descr` — descripteur de cible CORE — sont conservés TOUS LES DEUX.)
    MS.consigner(miss, "plan", plan_id=plan.plan_id,
                 providers=[s.provider for s in plan.steps],
                 selection=plan.selection)

    # ---------------------------------------------------------------- 3. policy
    # Une politique QUI NE PEUT PAS RÉPONDRE n'est pas une politique qui refuse :
    # l'exception remonte telle quelle (l'opérateur doit lire « OPA introuvable », jamais un
    # refus inventé ni une erreur générique). Ce qui manquait était la trace — mesuré le
    # 2026-08-30 sur un RUN réel de l'interface, cible admise et OPA absent : l'écran disait
    # la cause, le journal de mission s'arrêtait à « plan ».
    try:
        moteur = (policy_engine if policy_engine is not None
                  else PO.PolicyEngine(opa=CACHE_BIN / "opa"))
        # MCP-004 : plus de type de cible codé en dur. OPA lit le descripteur STRUCTURÉ
        # porté par le plan (`cible_descr` = Cible.to_dict()), donc le type réel de la
        # cible — pas un littéral "repository" qui mentirait sur une cible filesystem.
        decision = moteur.evaluer(plan, registre, cible_autorisee,
                                  confiance_cible=confiance_cible,
                                  profil=profil_eff.to_dict())
    except Exception as exc:
        _consigner_arret(miss, "policy_injoignable", exc)
        # Aucun outil n'est autorisé tant que la décision est injoignable : le ledger
        # le dit avec la CAUSE, pour que l'écran n'affiche pas six « non demarrés ».
        st = _ledger(miss, registre, plan.to_dict(),
                     {"allow": False, "motifs": [f"moteur de décision injoignable : {exc}"]},
                     [], [], {})
        # Le ledger est au journal — mais ni l'interface ni le CLI ne lisent le journal
        # au moment d'afficher un refus : ils ne connaissent QUE l'exception. Mesuré
        # le 2026-08-30 sur un run HTTP réel : l'écran disait « binaire OPA introuvable »
        # et se taisait sur les 5 outils absents et les 2 refusés par leurs conditions.
        # Porter l'état sur l'objet d'erreur évite d'inventer un second chemin de données.
        # Ajout pur : l'exception continue de remonter identique, type et message compris.
        try:
            exc.agnt_refus = {
                "motif": "policy_injoignable",
                # L'état de la garde d'export voyage avec le refus : un opérateur qui a demandé
                # `--egress=true` et voit « OPA introuvable » doit savoir que la demande a bien
                # été enregistrée et sur quel profil — sinon le refus se relit comme si rien n'avait
                # été demandé. Consigné ici, au même endroit que le ledger, par les mêmes champs
                # que `rapport.json`.
                "egress": dict(egress_info),
                "resume": STAT.resumer(st),
                "statuts": list(st),
                "conditions": (plan.to_dict().get("selection") or {}).get("conditions") or {},
                "plan": {"plan_id": plan.plan_id,
                         "providers": [s.provider for s in plan.steps]},
                "mission": str(miss.chemin),
            }
        except Exception:                                # jamais l'affichage ne tue le refus
            pass
        raise
    if not decision.allow:
        # Le plan est refusé : on s'arrête AVANT toute exécution.
        MS.consigner(miss, "arret", motif="policy", decision=list(decision.motifs))
        st = _ledger(miss, registre, plan.to_dict(),
                     {"allow": False, "motifs": list(decision.motifs)}, [], [], {})
        return Execution(plan=plan.to_dict(), statuts=st,
                         decision={"allow": False, "motifs": list(decision.motifs)},
                         intent=it.to_dict(), arret="policy", mission=miss.id,
                         # Un refus sans le nom du profil qui refuse ne se relit pas :
                         # « qui a décidé quoi, avec quelles limites » est la question.
                         profil=profil_eff.nom, egress=egress_info)

    # ---------------------------------------------------------------- 4. garde de chemin
    # OPA a autorisé la cible DEMANDÉE. Ici on vérifie ce qui est RÉELLEMENT accessible :
    # OPA ne peut pas savoir qu'un symlink sort du workspace.
    # Barrière de défense (2026-08-30) : une cible NON LOCALE n'a pas de chemin. Elle ne
    # peut pas arriver ici aujourd'hui (aucun provider compatible n'a survécu à
    # l'applicabilité), mais si un futur transport distant en laissait passer une, elle
    # ne doit jamais être traitée comme un pseudo-chemin local : refus explicite, pas
    # de conversion, pas de montage.
    if chemin_cible is None:
        raise PipelineError(
            f"cible non locale {cib.type!r} ({cib.reference_sure()}) sans chemin local : "
            f"le transport sandbox_cli ne peut pas la prendre en charge — elle doit être "
            f"routée par un transport distant enregistré, pas montée comme un Path")
    try:
        rapport_chemin = GC.verifier_cible(chemin_cible, [chemin_cible])
        for step in plan.steps:
            GC.verifier_args([*step.commande, *step.args])
    except Exception as exc:
        # Idem qu'à l'étape 3 : l'exception remonte intacte (c'est le serveur qui la dira au
        # client), mais le journal de mission doit porter la cause de l'arrêt. Sans cette ligne,
        # un dépôt dont le chemin fait sortir l'outil du montage ne laissait aucune trace —
        # exactement le cas que la campagne juge en E6 pour la politique, côté exécution.
        _consigner_arret(miss, "garde_chemin", exc)
        _ledger(miss, registre, plan.to_dict(), {"allow": True, "motifs": []},
                [], [], {})
        raise

    # ---------------------------------------------------------------- 5. exécution
    # La sortie vit SOUS la mission, pas dans un répertoire global partagé (multi-mission,
    # 2026-08-30). Chaque mission écrit ses raw_*/brut_* chez elle : rien à vider, rien à
    # se disputer entre deux exécutions concurrentes.
    sortie = _sortie_mission(miss)
    GC.verifier_sortie(sortie / "rapport.json", sortie)
    sbx = Sandbox(
        bwrap=shutil.which("bwrap") or "bwrap",
        egress_autorise=egress_accorde,
        racine_scan=chemin_cible,
        racine_regles=CACHE_REGLES,
        racine_db=CACHE_DB,
        sortie=sortie,
        gitconfig=RACINE / "gitconfig",
    )

    ctx = RUN.capturer(sbx, PO.POLICY_FILE, registre.empreinte())
    ctx.input_digest, ctx.input_commit, ctx.working_tree_dirty = RUN.digest_cible(chemin_cible)
    exec_ = Execution(plan=plan.to_dict(),
                      decision={"allow": True, "motifs": list(decision.motifs)},
                      intent=it.to_dict(),
                      profil=profil_eff.nom,
                      egress=egress_info,
                      run_id=RUN.nouveau_run_id(plan.plan_id, ctx, ctx.input_digest),
                      contexte=ctx.to_dict(),
                      chemin=rapport_chemin.to_dict(),
                      sortie=str(sortie))
    MS.consigner(miss, "contexte", run_id=exec_.run_id,
                 contexte_empreinte=ctx.contexte_empreinte,
                 input_digest=ctx.input_digest, input_commit=ctx.input_commit,
                 working_tree_dirty=ctx.working_tree_dirty)

    tous_findings = []
    trouves: dict[str, int] = {}      # provider -> observations normalisées (comptées à la source)
    # Dérivations déclaratives consommées par l'enrichissement des findings (plus bas) :
    # la catégorie vient des `domaines` de la capacité, le nom de l'outil de sa déclaration.
    domaines_du_provider = {}
    binaire_de_provider = {}
    for _p in registre.providers():
        dom = list(registre.capability(_p.capability).domaines or [])
        domaines_du_provider[_p.id] = dom[0] if dom else None
        binaire_de_provider[_p.id] = (_p.manifest.binaire if _p.manifest is not None
                                      else Path(_p.commande[0]).name)
    V = _ContexteVague(miss=miss, registre=registre, exec_=exec_, sbx=sbx, cible=chemin_cible,
                       sortie=sortie, ctx=ctx, trouves=trouves, tous_findings=tous_findings,
                       domaines=domaines_du_provider, binaires=binaire_de_provider,
                       transport_factories=dict(transport_factories or {}))
    _vague(plan.steps, V, plan.to_dict(), {"allow": True, "motifs": list(decision.motifs)},
           plan.cree_le, 1)

    # ---------------------------------------------------------------- 4b. escalade bornée
    # Un outil LANCÉ qui n'a pu analyser AUCUNE cible laisse une capacité non couverte.
    # Le laisser ainsi, c'est un trou de couverture qui se lit comme un résultat. D'où une
    # seconde vague, bornée, déclenchée par des faits déjà consignés (le ledger) et soumise à
    # la MÊME décision de politique que la vague 1. Ce n'est pas une boucle d'agent libre :
    # aucun nouveau plan à la demande d'un modèle, aucun critère deviné — un déclencheur
    # déclaré, un seul fournisseur suppléant par capacité, un plafond, et OPA ré-interroge
    # le plan ajouté avant qu'il tourne.
    if escalade and MAX_ESCALADE > 0:
        tentes = set(trouves) | {b["provider"] for b in exec_.raw}
        provisoire = STAT.construire(registre, plan.to_dict(),
                                     {"allow": True, "motifs": list(decision.motifs)},
                                     exec_.raw, exec_.couverture, trouves)
        declencheurs = STAT.declencheurs_escalade(provisoire, registre, tentes, MAX_ESCALADE)
        if declencheurs:
            noms = [d["suppleant"] for d in declencheurs]
            plan2 = P.construire(plan.requete, reference_cible, noms, registre,
                                 f"{plan.moteur_intent}+escalade",
                                 cible_descr=cib.to_dict())
            decision2 = None
            try:
                decision2 = moteur.evaluer(plan2, registre, cible_autorisee,
                                           confiance_cible=confiance_cible,
                                           profil=profil_eff.to_dict())
            except Exception as exc:                          # noqa: BLE001
                _consigner_arret(miss, "escalade_policy_injoignable", exc)
            for d in declencheurs:
                d["decision"] = ({"allow": bool(decision2.allow),
                                  "motifs": list(decision2.motifs)} if decision2
                                 else {"allow": False, "motifs": ["moteur de décision injoignable"]})
            exec_.escalades = declencheurs
            MS.consigner(miss, "escalade", declencheurs=declencheurs,
                         allow=bool(decision2.allow) if decision2 else False,
                         plan_id=(plan2.plan_id if decision2 and decision2.allow else ""))
            if decision2 and decision2.allow:
                _vague(plan2.steps, V, plan2.to_dict(),
                       {"allow": True, "motifs": list(decision2.motifs)}, plan2.cree_le, 2)
                for d in declencheurs:
                    d["execute"] = True
            else:
                # Refusée, l'escalade doit rester LISIBLE : sinon on a « essayé en secret ».
                for d in declencheurs:
                    d["execute"] = False
                    d["motif_refus"] = (", ".join(d["decision"]["motifs"])
                                        or "refus sans motif nommé")

    exec_.vague_parallele = min(outils_par_vague(), max(1, len(plan.steps)))
    exec_.statuts = _ledger(miss, registre, plan.to_dict(),
                            {"allow": True, "motifs": list(decision.motifs)},
                            exec_.raw, exec_.couverture, trouves)

    # ------------------------------------------------- 5. garde-fou secrets
    fuites = F.verifie_absence_secrets(tous_findings)
    if fuites:
        raise PipelineError("des secrets ont survécu à la normalisation : " + "; ".join(fuites))

    exec_.findings = [f.to_dict() for f in tous_findings]
    exec_.result_digest = RUN.digest_resultats(exec_.findings)

    # ---------------------------------------------------------------- 6. clustering v0
    exec_.clusters = clusterer.regrouper(tous_findings)

    # ---------------------------------------------------------------- 7. rapport
    exec_.rapport = _rapport(it, plan, exec_)
    exec_.mission = miss.id
    MS.consigner(miss, "cloture", findings=len(exec_.findings),
                 clusters=len(exec_.clusters.get("clusters") or []),
                 result_digest=exec_.result_digest)
    return exec_


def _rapport(it, plan, e: Execution) -> dict:
    par_outil = {}
    for c in e.couverture:
        par_outil[c["provider"]] = {
            "analysé": [t["chemin"] for t in c["cibles"]
                        if t["etat"] == "scanned_successfully"],
            "non_analysé": [{"cible": t["chemin"], "etat": t["etat"], "raison": t["raison"]}
                            for t in c["cibles"] if t["etat"] != "scanned_successfully"],
            "limites": c["limites_connues"],
        }
    return {
        "requete": it.requete,
        "capacites_demandees": list(it.capabilities),
        "motifs_intent": it.motifs,
        "plan_id": plan.plan_id,
        "plan_empreinte": plan.empreinte(),
        # Vue structurée consommable par l'UI : elle n'a pas à parser une commande
        # locale pour déterminer qu'un provider est MCP, ni à reconstruire les
        # versions serveur/outils depuis le journal.
        "providers": [{
            "id": s.provider,
            "capability": s.capability,
            "transport": s.transport,
            "provider_version": s.provider_version,
            "server": {"id": s.server_id, "version": s.server_version},
            "tool": {"name": s.tool, "version": s.tool_version},
            "protocol_version": s.protocol_version,
            "trust": s.trust,
            "target_types": list(s.target_types),
        } for s in plan.steps],
        "autorisation": e.decision,
        # La garde d'export dans le rapport, pas seulement dans le journal : c'est la première
        # question de quiconque relit des findings obtenus avec réseau (« l'outil a-t-il appelé
        # dehors ? »). Absent = exécution antérieure à LOT 3.
        "egress": e.egress,
        "outils_par_vague": e.vague_parallele,
        "findings": len(e.findings),
        "clustering": e.clusters["stats"],
        "clusters": e.clusters["clusters"],
        "non_regroupe": e.clusters["non_regroupe"],
        "couverture": par_outil,
        "statuts": e.statuts,
        "escalades": e.escalades,
    }


def main() -> int:
    # Ce point d'entrée direct doit avoir le même bootstrap que la CLI principale.
    # L'enregistrement est explicite et précède le Registry utilisé par executer().
    from mcp_bootstrap import initialiser_mcp
    import transports as CORE_TRANSPORTS
    initialiser_mcp(CORE_TRANSPORTS)
    requete = sys.argv[1] if len(sys.argv) > 1 else "Analyse la sécurité de mon dépôt"
    cible = Path(sys.argv[2]) if len(sys.argv) > 2 else RACINE / "testrepo"

    e = executer(requete, cible)
    sortie = Path(e.sortie) if e.sortie else (RACINE / "run")
    sortie.mkdir(parents=True, exist_ok=True)
    (sortie / "plan.json").write_text(json.dumps(e.plan, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    (sortie / "findings.json").write_text(json.dumps(e.findings, ensure_ascii=False, indent=2),
                                          encoding="utf-8")
    (sortie / "clusters.json").write_text(json.dumps(e.clusters, ensure_ascii=False, indent=2),
                                          encoding="utf-8")
    (sortie / "rapport.json").write_text(json.dumps(e.rapport, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    (sortie / "run.json").write_text(
        json.dumps({"execution_profile": e.profil,
                    # Présent ici aussi : `analyser.py` et `pipeline.main()` écrivent deux
                    # `run.json` du même fait, et l'un des deux omittrait la garde qu'un
                    # reliseur lirait comme « aucune garde d'export n'a existé ».
                    "egress": e.egress,
                    "plan_id": e.plan.get("plan_id"),
                    "input_digest": e.contexte.get("input_digest"),
                    "input_commit": e.contexte.get("input_commit", ""),
                    "working_tree_dirty": e.contexte.get("working_tree_dirty", False),
                    "execution_context_digest": e.contexte.get("contexte_empreinte"),
                    "run_id": e.run_id,
                    "result_digest": e.result_digest,
                    "contexte": e.contexte, "chemin": e.chemin},
                   ensure_ascii=False, indent=2), encoding="utf-8")

    if e.arret:
        print(f"requête      : {requete}")
        print(f"ARRÊT        : {e.arret}")
        if e.intent.get("question"):
            print(f"question     : {e.intent['question']}")
        if e.intent.get("motif"):
            print(f"motif        : {e.intent['motif']}")
        print("aucune exécution, aucun plan, aucun outil lancé")
        return 0

    r = e.rapport
    print(f"requête      : {r['requete']}")
    print(f"capacités    : {', '.join(r['capacites_demandees'])}")
    print(f"plan         : {r['plan_id']}  empreinte {r['plan_empreinte'][:16]}")
    print(f"run          : {e.run_id}  profil {e.profil}")
    print(f"  input_digest   : {e.contexte.get('input_digest')}  commit {e.contexte.get('input_commit') or '—'}"
          f"{'  (working tree MODIFIÉ)' if e.contexte.get('working_tree_dirty') else ''}")
    print(f"  contexte       : {e.contexte.get('contexte_empreinte')}")
    print(f"  result_digest  : {e.result_digest}")
    print(f"autorisation : allow={r['autorisation']['allow']} {r['autorisation']['motifs'] or ''}")
    print(f"findings     : {r['findings']}")
    print(f"clustering   : {r['clustering']['reduction']} "
          f"({r['clustering']['clusters']} clusters, "
          f"{r['clustering']['findings_non_regroupes']} non regroupés)")
    print("\n--- clusters ---")
    for c in r["clusters"]:
        print(f"  {c['cluster_id']}  {len(c['members']):>3} membres  "
              f"{c['confidence']:<7} {','.join(c['reason'])}  [{c['cle']}]")
    if r["non_regroupe"]:
        print(f"  non regroupés : {len(r['non_regroupe'])} ({', '.join(r['non_regroupe'][:6])})")
    print("\n--- couverture ---")
    for prov, c in r["couverture"].items():
        print(f"  {prov}")
        print(f"     analysé     : {c['analysé'] or '—'}")
        for na in c["non_analysé"]:
            print(f"     NON analysé : {na['cible']} [{na['etat']}] {na['raison']}")
        for lim in c["limites"]:
            print(f"     limite      : {lim}")
    print(f"\nécrit dans {sortie}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

