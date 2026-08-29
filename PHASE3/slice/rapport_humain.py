"""Rapport pour humain — Phase 8.

DEUX RAPPORTS, DEUX PUBLICS.

    rapport.md         pour l'ingénieur qui veut vérifier : traçable, complet,
                       reproductible. Machines, versions, empreintes, limites.
    rapport_humain.md  pour la personne qui décide quoi corriger : les problèmes
                       d'abord, en français simple, la machinerie tout en bas.

RÈGLE DE LANGAGE — la même que partout ailleurs dans le projet.

Un cluster est un regroupement d'observations, pas une vulnérabilité confirmée.
Donc on écrit :

    « signalé par deux outils différents »   ← ce qu'on sait
    « probable »                             ← ce que ça suggère
    « à vérifier »                           ← ce qu'il reste à faire

Jamais « votre code est vulnérable », jamais « faille confirmée ».
"""

from __future__ import annotations

from datetime import datetime, timezone

# Ordre de gravité, du plus urgent au moins urgent.
#
# Chaque outil a SA propre échelle, et il faut la traduire sans mentir :
#   Trivy     CRITICAL / HIGH / MEDIUM / LOW
#   Semgrep   ERROR / WARNING / INFO
#   Bandit    HIGH / MEDIUM / LOW
# Une échelle non reconnue vaut « indéterminée » : on n'invente pas une gravité.
GRAVITES = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
            "ERROR": 3, "WARNING": 2, "INFO": 1, "UNKNOWN": 0}

GRAVITE_LISIBLE = {"CRITICAL": "critique", "HIGH": "haute", "MEDIUM": "moyenne",
                   "LOW": "faible",
                   # Échelle Semgrep, traduite. La correspondance est dite une fois dans
                   # « Comment lire ce rapport », pas répétée dans chaque phrase.
                   "ERROR": "haute", "WARNING": "moyenne", "INFO": "faible",
                   "UNKNOWN": "indéterminée"}


def _gravite_cluster(cluster: dict, par_id: dict) -> tuple[str, int]:
    """Gravité la plus haute parmi les membres, et son rang."""
    meilleure, rang = "UNKNOWN", 0
    for m in cluster["members"]:
        f = par_id.get(m)
        if not f:
            continue
        g = str((f.get("severity") or {}).get("value", "UNKNOWN")).upper()
        r = GRAVITES.get(g, 0)
        if r > rang:
            meilleure, rang = g, r
    return meilleure, rang


def _paquets(cluster: dict, par_id: dict) -> list[str]:
    vus = []
    for m in cluster["members"]:
        f = par_id.get(m)
        if not f:
            continue
        p = (f.get("location") or {}).get("package")
        if p and p not in vus:
            vus.append(p)
    return vus


def _cves(cluster: dict, par_id: dict) -> list[str]:
    vus = []
    for m in cluster["members"]:
        f = par_id.get(m)
        if not f:
            continue
        rid = (f.get("source") or {}).get("original_rule_id") or ""
        if rid.upper().startswith("CVE-") and rid not in vus:
            vus.append(rid)
    return vus


def _outils(cluster: dict, par_id: dict) -> list[str]:
    vus = []
    for m in cluster["members"]:
        f = par_id.get(m)
        if not f:
            continue
        t = (f.get("source") or {}).get("tool")
        if t and t not in vus:
            vus.append(t)
    return vus


def _fichiers(cluster: dict, par_id: dict) -> list[str]:
    vus = []
    for m in cluster["members"]:
        f = par_id.get(m)
        if not f:
            continue
        fic = (f.get("location") or {}).get("file")
        if fic and fic not in vus:
            vus.append(fic)
    return vus


def _sans_gravite(par_id: dict) -> tuple[int, list[str]]:
    """Combien de findings n'ont AUCUNE gravité fournie, et par quels outils.

    « Aucune gravité » = valeur absente ou UNKNOWN. Ce n'est ni faible ni moyen :
    l'outil n'a rien évalué. Le rapport doit le dire au lieu de classer ces
    observations par défaut.
    """
    n, outils = 0, []
    for f in par_id.values():
        g = str((f.get("severity") or {}).get("value") or "UNKNOWN").upper()
        if g == "UNKNOWN" or g not in GRAVITES:
            n += 1
            t = (f.get("source") or {}).get("tool") or "?"
            if t not in outils:
                outils.append(t)
    return n, outils


def _phrase(cluster: dict, par_id: dict) -> str:
    """Une phrase, en français simple, qui dit ce qu'on sait.

    Elle ne prétend jamais à une confirmation.
    """
    raisons = cluster.get("reason") or []
    paquets = _paquets(cluster, par_id)
    cves = _cves(cluster, par_id)
    outils = _outils(cluster, par_id)
    fichiers = _fichiers(cluster, par_id)
    gravite, _ = _gravite_cluster(cluster, par_id)
    n = len(cluster["members"])

    lien = "same_dependency_usage" in raisons
    multi = len(outils) > 1

    if lien and paquets:
        p = paquets[0]
        debut = f"La librairie `{p}`"
        if cves:
            debut += f" présente {len(cves)} faille{'s' if len(cves) > 1 else ''} connue{'s' if len(cves) > 1 else ''}"
            debut += f" (gravité {GRAVITE_LISIBLE.get(gravite, gravite)})"
        if multi:
            debut += f", et {len(outils)} outils différents signalent un problème"
            debut += " dans la façon dont votre code l'utilise"
        return debut + "."

    if paquets and cves:
        return (f"La librairie `{paquets[0]}` présente {len(cves)} faille"
                f"{'s' if len(cves) > 1 else ''} connue"
                f"{'s' if len(cves) > 1 else ''} "
                f"(gravité {GRAVITE_LISIBLE.get(gravite, gravite)}).")

    if "ligne_proche" in raisons or "same_file" in raisons:
        if fichiers:
            nom = fichiers[0].split("/")[-1]
            return (f"{n} problème{'s' if n > 1 else ''} de même nature signalé"
                    f"{'s' if n > 1 else ''} dans `{nom}` "
                    f"(gravité {GRAVITE_LISIBLE.get(gravite, gravite)}).")

    if n == 1:
        f = par_id.get(cluster["members"][0]) if cluster["members"] else None
        msg = ((f or {}).get("evidence") or {}).get("message") or ""
        if fichiers:
            return (f"Un problème est signalé dans `{fichiers[0].split('/')[-1]}` : "
                    f"{str(msg)[:120].strip()}")
        return f"Un problème isolé est signalé (gravité {GRAVITE_LISIBLE.get(gravite, gravite)})."

    return (f"{n} observations regroupées "
            f"(gravité {GRAVITE_LISIBLE.get(gravite, gravite)}).")


def generer(e, cible) -> str:
    r = e.rapport
    ctx = e.contexte
    par_id = {f["id"]: f for f in e.findings}
    clusters = r.get("clusters", [])
    maintenant = datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M")

    # Tri : gravité d'abord, puis le nombre d'outils qui convergent.
    def cle(c):
        _, rang = _gravite_cluster(c, par_id)
        return (-rang, -len(_outils(c, par_id)), -len(c["members"]))

    classes = sorted(clusters, key=cle)
    importants = [c for c in classes
                  if _gravite_cluster(c, par_id)[1] >= GRAVITES["HIGH"]
                  or "same_dependency_usage" in (c.get("reason") or [])]
    autres = [c for c in classes if c not in importants]

    L = []
    A = L.append

    A("# Analyse de sécurité — ce qu'il faut regarder")
    A("")
    A(f"Dépôt analysé le {maintenant}.")
    A("")

    # ---------------------------------------------------------- l'essentiel
    non_reg = r.get("non_regroupe") or []
    if not clusters and not non_reg:
        # Vraiment aucun finding. Et encore : « rien signalé » ne veut pas dire
        # « rien à signaler ».
        A("## Aucun problème signalé")
        A("")
        A("Les outils n'ont rien signalé. **Cela ne veut pas dire qu'il n'y a rien** :")
        A("voir plus bas ce qui a été analysé, et ce qui ne l'a pas été.")
    elif not importants and not autres:
        # CAS QUI S'EST PRODUIT POUR DE VRAI : des findings existent, mais aucun n'est
        # « important » au sens du tri (gravité haute ou lien inter-outils). Le rapport
        # disait alors « Aucun problème signalé » alors qu'un secret de gravité HAUTE
        # avait été trouvé. Un secret passé sous silence est le pire défaut possible
        # pour un rapport de sécurité.
        A("## À regarder")
        A("")
        total_pb = len(clusters) + len(non_reg)
        A(f"**{total_pb} problème{'s' if total_pb > 1 else ''} signalé"
          f"{'s' if total_pb > 1 else ''}**, aucun regroupement possible.")
        A("")
        for i, c in enumerate(clusters, 1):
            A(f"**{i}.** {_phrase(c, par_id)}")
            A("")
        # Les findings non regroupés DOIVENT apparaître ici. C'est exactement le cas qui
        # a produit « Aucun problème signalé » alors qu'un secret de gravité HAUTE avait
        # été trouvé : un finding isolé n'est pas un finding inexistant.
        for m in non_reg:
            f = par_id.get(m)
            if not f:
                continue
            g = str((f.get("severity") or {}).get("value", "UNKNOWN")).upper()
            outil = (f.get("source") or {}).get("tool", "?")
            fic = str((f.get("location") or {}).get("file") or "?").split("/")[-1]
            ligne = (f.get("location") or {}).get("line")
            msg = str(((f.get("evidence") or {}).get("message") or ""))[:110]
            regle = str((f.get("source") or {}).get("original_rule_id") or "")
            A(f"- **{regle}** — gravité {GRAVITE_LISIBLE.get(g, g)} — "
              f"`{fic}`{':' + str(ligne) if ligne else ''} ({outil})")
            if msg:
                A(f"  {msg}")
            A("")
    else:
        A("## L'essentiel")
        A("")
        if not importants:
            # « Aucun problème grave » serait un mensonge par omission si des
            # observations n'ont AUCUNE gravité fournie : on ne peut pas dire
            # qu'elles ne sont pas graves, on sait seulement qu'elles n'ont pas
            # été évaluées (UNKNOWN ≠ LOW — décision 2026-08-28).
            inc = [c for c in autres if _gravite_cluster(c, par_id)[1] == 0]
            connus = [c for c in autres if _gravite_cluster(c, par_id)[1] > 0]
            if inc and not connus:
                n_obs = sum(len(c["members"]) for c in inc)
                A(f"**Aucune des {n_obs} observation{'s' if n_obs > 1 else ''} "
                  f"regroupée{'s' if n_obs > 1 else ''} n'a de gravité fournie** "
                  f"({len(inc)} regroupement{'s' if len(inc) > 1 else ''}) : "
                  f"rien n'a pu être classé par urgence. À examiner — voir "
                  f"« Gravité indéterminée » plus bas.")
            elif inc:
                A(f"Aucun problème à gravité haute signalé. {len(connus)} point"
                  f"{'s' if len(connus) > 1 else ''} secondaire"
                  f"{'s' if len(connus) > 1 else ''}, et {len(inc)} regroupement"
                  f"{'s' if len(inc) > 1 else ''} **sans gravité fournie** à examiner.")
            else:
                A(f"Aucun problème grave. {len(autres)} point"
                  f"{'s' if len(autres) > 1 else ''} secondaire"
                  f"{'s' if len(autres) > 1 else ''} à regarder.")
        else:
            A(f"**{len(importants)} point{'s' if len(importants) > 1 else ''} "
              f"à traiter en priorité**, sur {len(clusters)} au total.")
        A("")
        for i, c in enumerate(importants, 1):
            A(f"**{i}.** {_phrase(c, par_id)}")
            A("")
            outil_txt = " et ".join(f"`{t}`" for t in _outils(c, par_id))
            if len(_outils(c, par_id)) > 1:
                A(f"Signalé par {outil_txt}. Quand deux outils indépendants convergent, "
                  f"le problème est **probable** — mais il reste à vérifier.")
            else:
                A(f"Signalé par {outil_txt}.")
            cv = _cves(c, par_id)
            if cv:
                A(f"Failles concernées : {', '.join('`%s`' % x for x in cv[:6])}"
                  + (f" (+{len(cv) - 6})" if len(cv) > 6 else "") + ".")
            fic = _fichiers(c, par_id)
            if fic:
                # Chemins COMPLETS (dogfooding 2026-08-29) : le basename seul
                # affichait « package-lock.json, package-lock.json » pour
                # docs/package-lock.json + package-lock.json — deux fichiers
                # RÉELS rendus indiscernables. Un raccourci d'affichage ne doit
                # pas faire mentir la distinction.
                A(f"Fichiers : {', '.join('`%s`' % x for x in fic[:4])}"
                  + (f" (+{len(fic) - 4})" if len(fic) > 4 else "") + ".")
            A("")
            A(f"→ **À faire :** vérifier, puis corriger. {len(c['members'])} observation"
              f"{'s' if len(c['members']) > 1 else ''} dans le rapport détaillé.")
            A("")

    if autres:
        A("## À regarder ensuite")
        A("")
        for c in autres:
            g, _ = _gravite_cluster(c, par_id)
            A(f"- {_phrase(c, par_id)}")
        A("")

    if non_reg and (importants or autres):
        A(f"{len(non_reg)} observation{'s' if len(non_reg) > 1 else ''} isolée"
          f"{'s' if len(non_reg) > 1 else ''} : le regroupement n'a pas trouvé de lien. "
          f"Elles restent dans le rapport détaillé.")
        A("")

    # ------------------------------------------------- gravité indéterminée
    # Décision 2026-08-28 : UNKNOWN ≠ LOW ≠ MEDIUM. Quand un outil ne fournit
    # aucune gravité (checkov OSS : severity null sur 100 % de sa sortie), le
    # rapport l'explique au lieu de classer ces observations par défaut.
    n_inc, outils_inc = _sans_gravite(par_id)
    if n_inc:
        A("## Gravité « indéterminée » — ce que ça veut dire")
        A("")
        A(f"{n_inc} observation{'s' if n_inc > 1 else ''} de cette analyse n'ont "
          f"**aucune gravité fournie** : {' et '.join(f'`{t}`' for t in outils_inc)} "
          f"n'en {'renvoie' if len(outils_inc) == 1 else 'renvoient'} aucune pour "
          f"{'ces règles' if n_inc > 1 else 'cette règle'}. La valeur est absente de "
          f"leur sortie — ce n'est pas un oubli de ce rapport.")
        A("")
        A("- **Indéterminée ≠ faible.** Ces observations n'ont pas été évaluées : le "
          "risque réel peut être bénin comme sérieux. Leur attribuer une gravité "
          "serait inventer une information.")
        A("- **À faire :** prioriser selon l'impact de la ressource concernée, son "
          "exposition (Internet, réseau interne) et son contexte (production, "
          "expérimentation). Chaque observation est listée dans `rapport.md` avec "
          "son fichier, sa ligne et sa règle.")
        A("")

    # ---------------------------------------------------------- périmètre
    A("## Ce qui a été analysé")
    A("")
    couv = r.get("couverture") or {}
    for prov, c in couv.items():
        analysé = c.get("analysé") or []
        A(f"- **{prov}** : " + (", ".join(f"`{x.split('/')[-1]}`" for x in analysé[:5])
                                if analysé else "rien"))
    A("")

    non_analysés = [(prov, na) for prov, c in couv.items()
                    for na in (c.get("non_analysé") or [])]
    if non_analysés:
        A("### Ce qui n'a PAS été analysé")
        A("")
        A("**C'est important** : un problème dans ces éléments n'aurait pas été détecté.")
        A("")
        for prov, na in non_analysés:
            A(f"- `{str(na.get('cible', '?')).split('/')[-1]}` ({prov}) — {na.get('raison', '')}")
        A("")

    limites = [x for prov, c in couv.items() for x in (c.get("limites") or [])]
    if limites:
        A("### Limites de cette analyse")
        A("")
        for x in limites:
            A(f"- {x}")
        A("")

    # ---------------------------------------------------------- vocabulaire
    A("## Comment lire ce rapport")
    A("")
    A("| Ce qu'on dit | Ce que ça veut dire |")
    A("|---|---|")
    A("| observé | un outil a produit ce résultat |")
    A("| probable | plusieurs outils convergent, ou une faille connue est concernée |")
    A("| à vérifier | personne n'a encore confirmé que c'est exploitable |")
    A("| gravité indéterminée | l'outil n'a fourni aucune gravité : non évalué — "
      "ce n'est ni faible ni moyen |")
    A("")
    A("Rien dans ce rapport n'est une vulnérabilité **confirmée**. Une confirmation demande")
    A("un test réel, ou une correction suivie d'une nouvelle analyse.")
    A("")

    # ---------------------------------------------------------- machinerie, tout en bas
    A("---")
    A("")
    A("## Détails techniques")
    A("")
    A("_Pour vérifier, rejouer ou auditer cette analyse. Le rapport complet est dans_")
    A("_`rapport.md` du même dossier._")
    A("")
    A(f"- dépôt : `{cible}`")
    A(f"- commit : `{ctx.get('input_commit') or '—'}`")
    A(f"- identifiants : plan `{r.get('plan_id')}` · run `{e.run_id}`")
    A(f"- empreintes : cible `{ctx.get('input_digest')}` · "
      f"contexte `{ctx.get('contexte_empreinte')}` · résultat `{e.result_digest}`")
    A(f"- profil : `{e.profil}`")
    A(f"- {len(e.findings)} observations, {len(clusters)} regroupements")
    A("")

    return "\n".join(L)

