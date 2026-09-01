/**
 * Normalisation d'une mission RÉELLE (réponse `/api/runs/<id>` quand
 * `statut === "termine"`) vers le modèle de vues de la console.
 *
 * On ne fabrique rien : chaque champ vient d'un artefact de l'archive. Ce qui
 * est absent reste absent (gravité UNKNOWN, fichier null…) — jamais inventé.
 */
import type { RunEtat, FindingRaw, ClusterRaw } from "./api";
import type { Observation, Cluster, Couverture, Gravite } from "./data/rejeu";

export interface JournalLigne {
  tag: string;
  msg: string;
  detail?: string;
}

export interface LiveData {
  cible: string;
  mission: string;
  observations: Observation[];
  clusters: Cluster[];
  couverture: Couverture[];
  journal: JournalLigne[];
  markdown: string;
}

function graviteDe(valeur?: string): Gravite {
  const v = (valeur || "").toUpperCase();
  if (!v) return "UNKNOWN";
  if (/(CRITICAL|HIGH|ERROR|FATAL)/.test(v)) return "HIGH";
  if (/(MEDIUM|WARNING|WARN|LOW|INFO|MODERATE)/.test(v)) return "MEDIUM";
  return "UNKNOWN";
}

function observationDe(f: FindingRaw, i: number): Observation {
  const outil = f.source?.tool || "?";
  const regle = f.source?.canonical_rule_id || f.source?.original_rule_id || "—";
  return {
    id: f.id || `OBS-${i + 1}`,
    outil,
    regle,
    message: f.evidence?.message || "(sans message)",
    fichier: f.location?.file || "—",
    ligne: typeof f.location?.line === "number" ? f.location.line : null,
    gravite: graviteDe(f.severity?.value),
    cadre: f.location?.asset || outil,
  };
}

function clusterDe(c: ClusterRaw, i: number): Cluster {
  const membres = c.members || [];
  const cle = c.cle || "";
  // La clé du moteur est du type "fichier:app.py" ou "paquet:…" : on en extrait
  // le fichier quand c'est un fichier, sans forcer les autres coordonnées.
  const fichier = cle.startsWith("fichier:") ? cle.slice("fichier:".length) : cle || null;
  return {
    id: c.cluster_id || `CL-${i + 1}`,
    membres,
    motifs: c.reason || [],
    fichier,
    gravite: "UNKNOWN", // la gravité d'un cluster n'est jamais déduite par l'écran
  };
}

export function normaliser(run: RunEtat): LiveData {
  const d = run.donnees || {};
  const chaine = d.chaine || {};
  const resume = run.resume || {};

  const observations: Observation[] = (d.findings || []).map(observationDe);

  const cl = d.clusters || {};
  const clusters: Cluster[] = [
    ...(cl.clusters || []),
    ...(cl.clusters_inter_outils || []),
  ].map(clusterDe);

  // Couverture : l'objet `chaine.couverture` est indexé par nom d'outil et ne
  // liste QUE ce qui a réellement tourné (ground truth de l'archive).
  const couv = chaine.couverture || {};
  const couverture: Couverture[] = Object.entries(couv).map(([outil, val]) => {
    const analyses = (val && (val as { analysé?: string[] }).analysé) || [];
    const limites = (val && (val as { limites?: string[] }).limites) || [];
    return {
      capacite: outil,
      provider: outil,
      risque: "passif" as const,
      statut: analyses.length ? ("exécuté" as const) : ("non applicable" as const),
      detail:
        (analyses.length ? `analysé : ${analyses.join(", ")}` : "aucune cible analysée") +
        (limites.length ? ` · limite : ${limites[0]}` : ""),
    };
  });

  // Journal vivant, dérivé des artefacts (pas rejoué).
  const journal: JournalLigne[] = [];
  const mission = resume.mission || d.run?.mission || run.mission_id || "—";
  journal.push({ tag: "sys", msg: `mission ouverte — ${mission}` });
  if (resume.moteur) journal.push({ tag: "intent", msg: `moteur : ${resume.moteur}` });
  if (chaine.requete_canonique)
    journal.push({ tag: "intent", msg: `requête canonique : « ${chaine.requete_canonique} »` });
  for (const c of couverture)
    journal.push({
      tag: "tool",
      msg: `${c.provider} — ${c.statut}`,
      detail: c.detail,
    });
  if (run.statut === "refuse" || resume.statut === "conditions")
    journal.push({
      tag: "opa",
      msg: "refus nommé (fail-closed)",
      detail: resume.motif || run.erreur || "aucun outil exécutable dans ces conditions",
    });
  if (run.statut === "termine")
    journal.push({
      tag: "done",
      msg: `mission close — ${observations.length} observation(s) · ${clusters.length} regroupement(s)`,
      detail: "rapport écrit par le moteur, sans invention de gravité",
    });

  return {
    cible: chaine.cible || run.cible || "—",
    mission,
    observations,
    clusters,
    couverture,
    journal,
    markdown: d.rapport_markdown || "",
  };
}
