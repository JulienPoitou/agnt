// Libellés et faits de la matrice gate-002.
// Les descriptions de cas sont citées du README canonique :
// docs/coordination/captures/gate-002-product-api/README.md (main @ 5f5e09d6).
// Aucune traduction de token n'invente un fait : les jetons du contrat sont
// rendus tels quels quand aucun libellé n'est connu.

import type { CaptureBody } from "@/lib/api";
import { isApiError, isHistoryList, isMissionDetail } from "@/lib/api";

/** Clé de vue = body_file de la capture ; alias mission_id -> body_file. */
export const ROLE_LABELS: Record<string, { label: string; note: string }> = {
  list: { label: "LISTE", note: "listing paginé · GET /api/missions?limit=25" },
  pagination_probe: { label: "PAGINATION", note: "limit=1 : un curseur next_cursor est réellement publié" },
  status_filter: { label: "FILTRE · STATUS", note: "status=termine — seules les missions terminées" },
  target_filter: { label: "FILTRE · CIBLE", note: "target_type=repository — les cibles non-repos sont écartées" },
  empty_list: { label: "LISTE VIDE", note: "HTTP 200 + items: [] — vide prouvé, ni erreur ni refus" },
  invalid_filter: { label: "FILTRE INVALIDE", note: "HTTP 400 — requête refusée avant exécution" },
};

/** mission_id -> cas exercé, cité du tableau « Matrice » du README des captures. */
export const MISSION_CASES: Record<string, { cas: string; fait: string }> = {
  "m-20260830T120005Z-00000001": {
    cas: "zero",
    fait: "terminée, 0 finding prouvé (rien_trouve + 3 cibles analysées)",
  },
  "m-20260830T120004Z-00000002": { cas: "findings", fait: "terminée, 2 findings normalisés + 1 cluster" },
  "m-20260830T120003Z-00000003": {
    cas: "refused",
    fait: "refus de politique pré-Run → non_autorise, jamais zéro",
  },
  "m-20260830T120002Z-00000004": {
    cas: "unavailable",
    fait: "binaire absent → unavailable, détection non_evalue",
  },
  "m-20260830T120001Z-00000005": { cas: "failed", fait: "code retour 1 → echoue, jamais zéro" },
  "m-20260830T120000Z-00000006": { cas: "timeout", fait: "deadline dépassée → timed_out" },
  "m-20260830T115959Z-00000007": {
    cas: "cancelled",
    fait: "mission close pendant l'exécution → cancelled",
  },
  "m-20260830T115958Z-00000008": {
    cas: "non_applicable",
    fait: "cible url, provider écarté à l'applicabilité",
  },
  "m-20260830T115957Z-00000009": {
    cas: "incomplete",
    fait: "artefacts absents → partial/missing_artifacts, rien de fabriqué",
  },
  "m-20260830T115956Z-0000000a": {
    cas: "unknown",
    fait: "type d'événement inconnu du lecteur → unknown_event_recorded, payload jamais publié",
  },
  "m-20260830T115955Z-0000000b": {
    cas: "mcp",
    fait: "provenance consignée projetée en allowlist (projection vérifiée, acquisition non)",
  },
};

const STATUS_LABELS: Record<string, string> = {
  termine: "Terminé",
  refuse: "Refusé",
  erreur: "Erreur",
  inconnu: "Inconnu",
  en_file: "En file",
  en_cours: "En cours",
};

export function statusLabel(token: string): string {
  return STATUS_LABELS[token] ?? token;
}

// Libellés d'affichage des jetons de valeur observés dans les captures.
// Un jeton absent de la table s'affiche BRUT : le front ne devine pas.
const TOKEN_LABELS: Record<string, string> = {
  applicable: "applicable",
  non_applicable: "non applicable",
  selectionne: "sélectionné",
  non_selectionne: "non sélectionné",
  remplie: "remplie",
  autorise: "autorisé",
  non_autorise: "refusé par la politique",
  non_evalue: "non évalué",
  disponible: "disponible",
  indisponible: "indisponible",
  inconnu: "inconnu",
  termine: "terminée",
  echoue: "échouée",
  timed_out: "expirée (deadline)",
  cancelled: "annulée",
  unavailable: "indisponible",
  non_lance: "non lancée",
  rien_trouve: "rien trouvé",
  findings_presents: "findings présents",
  recorded: "consigné",
  derived: "dérivé",
  unknown: "inconnu",
  complete: "complète",
  partial: "partielle",
};

export function tokenLabel(token: string | undefined): string {
  if (token === undefined) return "non consigné";
  return TOKEN_LABELS[token] ?? token;
}

export type ViewKind = "history" | "error" | "detail";

export interface ActiveView {
  kind: ViewKind;
  body: CaptureBody;
  path: string;
  status: number;
  role: string;
  key: string;
}

/** Résout une clé de vue (body_file ou mission_id) en capture active. */
export function resolveView(
  key: string | undefined,
  captures: { role: string; path: string; status: number; body_file: string; body: CaptureBody }[]
): ActiveView | undefined {
  if (!key) return undefined;
  const found = captures.find((c) => {
    if (c.body_file === key) return true;
    return c.role === "detail" && isMissionDetail(c.body) && c.body.mission.mission_id === key;
  });
  if (!found) return undefined;
  const kind: ViewKind = isHistoryList(found.body) ? "history" : isApiError(found.body) ? "error" : "detail";
  return { kind, body: found.body, path: found.path, status: found.status, role: found.role, key: found.body_file };
}
