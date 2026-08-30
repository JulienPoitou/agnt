"""Rapport Markdown — Phase 4.

Généré par du code DÉTERMINISTE, sans LLM. Ce choix n'est pas esthétique : si le texte
changeait à chaque exécution, on ne pourrait plus savoir si une divergence vient des
outils, des findings ou du modèle.

RÈGLE DE SÉMANTIQUE — la plus importante de ce fichier.

Le système produit des OBSERVATIONS et des CORRÉLATIONS. Il ne confirme pas de
vulnérabilité. Écrire « votre dépôt contient 8 vulnérabilités » alors qu'on a établi
« 8 clusters d'observations provenant de 65 findings » serait une sur-affirmation.

Échelle employée, et rien d'autre :

    observé         un outil a produit ce résultat
    corrélé         plusieurs observations sont reliées entre elles
    probable        une corrélation renforce la plausibilité
    vérifié         un re-scan ou une preuve explicite le confirme
    non déterminé   le système ne peut pas trancher

Jamais : « vulnérable », « confirmé », « votre dépôt contient N vulnérabilités ».
"""

from __future__ import annotations

# Une seule politique d'échappement pour les deux rendeurs du projet : importer celle de
# rapport_humain plutôt que d'en réécrire une seconde. Deux copies finissent toujours par
# diverger, et c'est exactement le défaut que C3b a montré sur le masquage des secrets.
from rapport_humain import sur as _sur

from datetime import datetime, timezone

# Correspondance raison → phrase lisible. Toute raison inconnue doit apparaître telle
# quelle : mieux vaut un terme technique visible qu'une traduction inventée.
RAISONS_LISIBLES = {
    "same_package": "même paquet",
    "related_dependency": "dépendances liées",
    "same_asset": "même cible",
    "same_file": "même fichier",
    "ligne_proche": "lignes proches",
    "same_rule": "même règle",
    "cross_tool": "observations provenant d'outils différents",
}

CONFIANCES = {"high": "élevée", "medium": "moyenne", "low": "faible", "none": "aucune"}


def _l(x) -> str:
    return "—" if x in (None, "", []) else str(x)


def _raison_lisible(raison: list[str]) -> str:
    out = []
    for r in raison:
        if r.startswith("tools:"):
            out.append(f"outils concernés : {r.split(':', 1)[1]}")
        else:
            out.append(RAISONS_LISIBLES.get(r, r))
    return " · ".join(out) if out else "—"


def generer(e, cible) -> str:
    """Produit le rapport Markdown. `e` est une Execution du pipeline."""
    r = e.rapport
    ctx = e.contexte
    ids = {f["id"]: f for f in e.findings}
    maintenant = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    n_findings = len(e.findings)
    n_clusters = len(r.get("clusters", []))
    n_non_regroupe = len(r.get("non_regroupe", []))
    n_inter = len(e.clusters.get("clusters_inter_outils", []))

    L = []
    A = L.append

    # ============================================================ 1. RÉSUMÉ
    A("# Rapport d'analyse de sécurité")
    A("")
    A("> **Ce que ce rapport est.** Une synthèse d'**observations** produites par des outils,")
    A("> et de **corrélations** entre ces observations. Ce n'est pas une confirmation de")
    A("> vulnérabilité. Aucun résultat n'est marqué « vérifié » sans preuve explicite.")
    A("")
    A("## 1. Résumé")
    A("")
    A("| | |")
    A("|---|---|")
    A(f"| Dépôt analysé | `{cible}` |")
    A(f"| Commit | `{_l(ctx.get('input_commit'))}` |")
    A(f"| Modifications non commitées | {'oui' if ctx.get('working_tree_dirty') else 'non'} |")
    A(f"| Digest de la cible | `{_l(ctx.get('input_digest'))}` |")
    A(f"| Date du scan | {maintenant} |")
    A(f"| Profil d'exécution | `{_l(e.profil)}` |")
    A(f"| Statut | {_statut(e, n_findings)} |")
    A("")
    A(f"**{n_findings} observations**, regroupées en **{n_clusters} clusters**"
      + (f", dont {n_inter} reliant plusieurs outils" if n_inter else "")
      + (f". {n_non_regroupe} observation(s) non regroupée(s)." if n_non_regroupe else "."))
    A("")
    A("Compter des clusters n'équivaut pas à compter des vulnérabilités : un cluster est un")
    A("regroupement d'observations, pas un problème confirmé.")
    A("")

    # ============================================================ 2. PÉRIMÈTRE
    A("## 2. Périmètre et couverture")
    A("")
    A("### Outils")
    A("")
    A("| Outil | Version |")
    A("|---|---|")
    for nom, ver in sorted((ctx.get("outils") or {}).items()):
        # Une version illisible est affichée telle quelle : on ne prétend pas qu'un outil
        # a servi si on ne peut pas prouver laquelle de ses versions a servi.
        A(f"| `{_sur(nom, dans_code_span=True)}` | `{_sur(ver, dans_code_span=True)}` |")
    A("")
    A("### Ce qui a été analysé, et ce qui ne l'a pas été")
    A("")
    for prov, c in (r.get("couverture") or {}).items():
        A(f"**`{prov}`**")
        A("")
        if c.get("analysé"):
            A("- analysé : " + ", ".join(
                f"`{_sur(x, dans_code_span=True)}`" for x in c["analysé"]))
        for na in c.get("non_analysé", []):
            A(f"- **non analysé** : `{_sur(na['cible'], dans_code_span=True)}` — "
              f"`{_sur(na['etat'], dans_code_span=True)}` — {_sur(str(na['raison']))}")
        for lim in c.get("limites", []):
            A(f"- limite : {lim}")
        A("")
    A("### Règles et base de données")
    A("")
    A("| Élément | Digest |")
    A("|---|---|")
    for nom, dg in sorted((ctx.get("regles") or {}).items()):
        A(f"| règles `{_sur(nom, dans_code_span=True)}` | `{dg}` |")
    A(f"| base Trivy | `{_l(ctx.get('base_trivy'))}` |")
    A(f"| politique | `{_l(ctx.get('policy'))}` |")
    A(f"| registre | `{_l(ctx.get('registre'))}` |")
    A("")
    A("La base de vulnérabilités est figée au moment du pré-chauffage : les CVE publiées")
    A("depuis ne sont pas détectées.")
    A("")

    # ============================================================ 3. CLUSTERS
    A("## 3. Observations regroupées")
    A("")
    if not r.get("clusters"):
        A("_Aucun regroupement._")
        A("")
    for c in r.get("clusters", []):
        membres = [m for m in c["members"] if m in ids]
        outils = sorted({ids[m]["source"]["tool"] for m in membres})
        cve = sorted({ids[m]["source"]["original_rule_id"] for m in membres
                      if ids[m]["source"]["tool"] == "trivy"})
        paquets = sorted({ids[m]["source"].get("package") for m in membres
                          if ids[m]["source"].get("package")})
        fichiers = sorted({ids[m]["location"].get("file") for m in membres
                           if ids[m]["location"].get("file")})
        inter = "cross_tool" in c["reason"]

        A(f"### {c['cluster_id']} — {len(membres)} observations")
        A("")
        A("| | |")
        A("|---|---|")
        A(f"| Statut | {'**corrélé entre outils**' if inter else 'observé'} |")
        A(f"| Confiance | {CONFIANCES.get(c['confidence'], c['confidence'])} |")
        A(f"| Raison | {_raison_lisible(c['reason'])} |")
        A(f"| Outils | {', '.join('`%s`' % _sur(x, dans_code_span=True) for x in outils)} |")
        if paquets:
            A(f"| Paquets | {', '.join('`%s`' % _sur(x, dans_code_span=True) for x in paquets)} |")
        if cve:
            A(f"| CVE | {', '.join('`%s`' % _sur(x, dans_code_span=True) for x in cve[:8])}"
              + (f" (+{len(cve) - 8})" if len(cve) > 8 else "") + " |")
        if fichiers:
            # mode span : c'est ici que le nom d'un fichier hostile sortait de son `code
            # span` et devenait une ligne du document (constat C6 de la campagne adverse)
            A(f"| Fichiers | {', '.join('`%s`' % _sur(x, dans_code_span=True) for x in fichiers[:5])}"
              + (f" (+{len(fichiers) - 5})" if len(fichiers) > 5 else "") + " |")
        A(f"| Findings sources | {', '.join('`%s`' % m for m in membres)} |")
        A("")
        if inter:
            A("> Plusieurs outils indépendants ont produit des observations reliées. Cela")
            A("> **renforce la plausibilité**, cela ne confirme pas l'exploitabilité.")
            A("")

    if n_non_regroupe:
        A("### Observations non regroupées")
        A("")
        A("Le regroupement est conservateur : quand le système ne peut pas justifier un lien,")
        A("il ne regroupe pas. Ces observations restent individuelles.")
        A("")
        for m in r["non_regroupe"]:
            f = ids.get(m)
            if f:
                A(f"- `{_sur(m, dans_code_span=True)}` — {_sur(f['source']['tool'])} — "
                  f"{f['identity']['canonical_rule_id']} — "
                  f"{_sur(_l(f['location'].get('file')), dans_code_span=True)}"
                  f":{_l(f['location'].get('line'))}")
        A("")

    # ============================================================ 4. PREUVES
    A("## 4. Preuves")
    A("")
    A("Extrait des observations, limité aux premières. Le détail complet est dans")
    A("`findings.json` et les fichiers `raw_*.json`.")
    A("")
    for f in e.findings[:10]:
        loc = f["location"]
        src = f["source"]
        ev = f.get("evidence") or {}
        A(f"**`{_sur(f['id'], dans_code_span=True)}`** — {_sur(src['tool'])} — "
          f"`{_sur(f['identity']['canonical_rule_id'], dans_code_span=True)}`")
        A("")
        A(f"- localisation : `{_sur(_l(loc.get('file')), dans_code_span=True)}` "
          f"ligne {_l(loc.get('line'))}")
        if loc.get("package"):
            pm = src.get("package_mapping") or {}
            A(f"- paquet : `{_sur(loc['package'], dans_code_span=True)}` "
              f"(mapping : {pm.get('method', '?')}, confiance {pm.get('confidence', '?')})")
        if src.get("version_installee"):
            A(f"- version installée : `{src['version_installee']}` → "
              f"corrigée dans `{_l(src.get('version_corrigee'))}`")
        sev = f.get("severity") or {}
        A(f"- sévérité : {sev.get('value', '?')} _(origine : {sev.get('origine', '?')})_")
        if ev.get("message"):
            A(f"- message : {_sur(str(ev['message'])[:220])}")
        if ev.get("extrait"):
            A(f"- extrait : `{_sur(str(ev['extrait'])[:160], dans_code_span=True)}`")
        if ev.get("secret"):
            A(f"- secret : `{_sur(ev['secret'], dans_code_span=True)}`")
        A(f"- règle source : `{_sur(src.get('original_rule_id'), dans_code_span=True)}`")
        A("")
    if len(e.findings) > 10:
        A(f"_{len(e.findings) - 10} observations supplémentaires dans `findings.json`._")
        A("")
    A("**Distinction à conserver :** une observation est ce qu'un outil a produit. Une")
    A("corrélation relie des observations. Aucune des deux ne constitue une vulnérabilité")
    A("vérifiée — cela demanderait un re-scan après correction, ou une preuve d'exploitabilité.")
    A("")

    # ============================================================ 5. REPRODUCTIBILITÉ
    A("## 5. Reproductibilité")
    A("")
    A("| Identifiant | Valeur | Nature |")
    A("|---|---|---|")
    A(f"| `plan_id` | `{_l(r.get('plan_id'))}` | déterministe |")
    A(f"| `input_digest` | `{_l(ctx.get('input_digest'))}` | déterministe |")
    A(f"| `execution_context_digest` | `{_l(ctx.get('contexte_empreinte'))}` | déterministe |")
    A(f"| `result_digest` | `{_l(e.result_digest)}` | déterministe |")
    A(f"| `run_id` | `{_l(e.run_id)}` | **unique** (nonce) |")
    A("")
    A("Même plan + même cible + même contexte → même `result_digest`. Le `run_id` diffère à")
    A("chaque exécution : c'est voulu, il identifie l'exécution, pas le résultat.")
    A("")
    A("### Limites du profil d'exécution")
    A("")
    lim = (ctx.get("sandbox") or {})
    A(f"- processus : {_l(lim.get('max_processus'))}")
    A(f"- temps CPU : {_l(lim.get('max_cpu_secondes'))} s")
    A(f"- taille de fichier : {_l(lim.get('max_fichier_octets'))} octets")
    A(f"- timeout : {_l(lim.get('timeout_secondes'))} s")
    A(f"- **mémoire : {_l(lim.get('memoire'))}**")
    A("")
    A("La mémoire n'est pas bornée. Ce rapport n'est donc valable que pour un dépôt de")
    A("confiance `controlled`, avec des outils passifs. Dépôt non fiable, service exposé,")
    A("multi-utilisateur, scan parallèle ou outil actif : **refusés par la politique**.")
    A("")

    # ============================================================ 6. ARTEFACTS
    A("## 6. Artefacts")
    A("")
    A("| Fichier | Contenu |")
    A("|---|---|")
    A("| `rapport_humain.md` | **à lire en premier** : les problèmes, en français simple |")
    A("| `rapport.md` | ce document : traçabilité et vérification |")
    A("| `manifeste.json` | identifiants, digests, profil, couverture |")
    A("| `plan.json` | le plan typé autorisé par la politique |")
    A("| `findings.json` | findings normalisés, identité source et canonique |")
    A("| `clusters.json` | regroupements et raisons |")
    A("| `run.json` | contexte d'exécution complet |")
    A("| `raw_*.json` | sorties brutes des outils, non retraitées |")
    A("| `rapport.sarif` | export SARIF des observations |")
    A("")
    A("---")
    A("")
    A("_Rapport généré de façon déterministe, sans modèle de langage. À profil, cible et")
    A("contexte identiques, ce texte est reproductible — seuls la date et le `run_id` varient._")
    A("")
    return "\n".join(L)


def _statut(e, n_findings: int) -> str:
    if e.arret:
        return f"**interrompu** ({e.arret})"
    if n_findings == 0:
        return "**aucune observation** — voir la couverture, l'absence de résultat n'est pas une preuve d'absence de risque"
    return f"**{n_findings} observations à examiner**"

