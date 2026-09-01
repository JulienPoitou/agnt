/**
 * Client de l'API moteur réelle (PHASE3/interface/api.py) — même contrat que
 * l'interface vanilla. Aucune logique de sécurité ici : on transmet et on
 * relit ce que le moteur écrit dans son archive de mission.
 *
 * En dev, Vite proxifie `/api` → http://127.0.0.1:8141 (voir vite.config.ts).
 * Si l'API ne répond pas, l'appel REJETTE : c'est l'appelant qui décide de
 * retomber sur le rejeu, en l'affichant comme rejeu (jamais comme un résultat).
 */

export interface CibleApi {
  nom: string;
  chemin: string;
  fichiers_vus: string[];
  langages: string[];
}

export interface CapaciteApi {
  id: string;
  description: string;
}

export interface CapacitesApi {
  confiances: string[];
  moteurs: string[];
  capacites: CapaciteApi[];
}

/** Forme brute d'un finding dans l'archive (donnees_exemple.json = schéma réel). */
export interface FindingRaw {
  id: string;
  source?: { tool?: string; canonical_rule_id?: string; original_rule_id?: string };
  location?: { file?: string; line?: number | null; asset?: string };
  severity?: { value?: string; origine?: string };
  evidence?: { message?: string; extrait?: string };
  statut?: string;
}

export interface ClusterRaw {
  cluster_id: string;
  confidence?: string;
  reason?: string[];
  members?: string[];
  cle?: string;
}

/** Réponse de GET /api/runs/<id> — seules les clés qu'on consomme. */
export interface RunEtat {
  id: string;
  statut: "en_file" | "en_cours" | "termine" | "refuse" | "erreur";
  question?: string;
  cible?: string;
  mission_id?: string | null;
  detail_href?: string | null;
  position?: number;
  code?: number;
  resume?: {
    statut?: string;
    moteur?: string;
    confiance_cible?: string;
    mission?: string;
    findings?: number;
    clusters_inter_outils?: number;
    motif?: string;
    sortie?: string;
  };
  donnees?: {
    chaine?: {
      requete?: string | null;
      requete_canonique?: string | null;
      cible?: string | null;
      steps?: Array<{ capability?: string; provider?: string; risque?: string }>;
      couverture?: Record<string, { analysé?: string[]; "non_analysé"?: unknown[]; limites?: string[] }>;
      statuts?: Array<{ outil?: string; provider?: string; statut?: string; etape?: string }> | null;
    };
    findings?: FindingRaw[] | null;
    findings_absents?: boolean;
    clusters?: {
      clusters?: ClusterRaw[];
      clusters_inter_outils?: ClusterRaw[];
      non_regroupe?: unknown[];
      stats?: Record<string, number>;
    } | null;
    rapport_markdown?: string;
    run?: { mission?: string | null; moteur?: string; profil?: string; egress?: unknown };
  };
  // En cas de refus nommé : l'API peut porter le motif à plusieurs endroits.
  refus?: { motif?: string; statuts?: unknown } | null;
  erreur?: string | null;
}

async function json<T>(url: string, options?: RequestInit): Promise<T> {
  const r = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!r.ok) {
    let detail = "";
    try {
      const b = await r.json();
      detail = (b && (b.erreur || b.error?.message)) || "";
    } catch {
      /* corps non-JSON */
    }
    throw new Error(`HTTP ${r.status}${detail ? ` — ${detail}` : ""}`);
  }
  return (await r.json()) as T;
}

export const api = {
  vivante: async (): Promise<boolean> => {
    // Un simple GET capacités sert de ping ; le rejet = API absente.
    await json<CapacitesApi>("/api/capacites");
    return true;
  },
  cibles: () => json<{ cibles: CibleApi[] }>("/api/cibles").then((r) => r.cibles),
  capacites: () => json<CapacitesApi>("/api/capacites"),
  lancer: (question: string, cible: string, opts: { moteur?: string; confiance?: string } = {}) =>
    json<{ id: string; statut: string; position?: number }>("/api/runs", {
      method: "POST",
      body: JSON.stringify({
        question,
        cible,
        moteur: opts.moteur || "auto",
        confiance: opts.confiance || "controlled",
      }),
    }),
  etat: (id: string) => json<RunEtat>(`/api/runs/${id}`),
};
