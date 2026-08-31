import { z } from "zod";

import captureManifestJson from "../../public/data/gate-002-product-api/capture-manifest.json";
import detail01Json from "../../public/data/gate-002-product-api/detail-01-m-20260830T120005Z-00000001.json";
import detail02Json from "../../public/data/gate-002-product-api/detail-02-m-20260830T120004Z-00000002.json";
import detail03Json from "../../public/data/gate-002-product-api/detail-03-m-20260830T120003Z-00000003.json";
import detail04Json from "../../public/data/gate-002-product-api/detail-04-m-20260830T120002Z-00000004.json";
import detail05Json from "../../public/data/gate-002-product-api/detail-05-m-20260830T120001Z-00000005.json";
import detail06Json from "../../public/data/gate-002-product-api/detail-06-m-20260830T120000Z-00000006.json";
import detail07Json from "../../public/data/gate-002-product-api/detail-07-m-20260830T115959Z-00000007.json";
import detail08Json from "../../public/data/gate-002-product-api/detail-08-m-20260830T115958Z-00000008.json";
import detail09Json from "../../public/data/gate-002-product-api/detail-09-m-20260830T115957Z-00000009.json";
import detail10Json from "../../public/data/gate-002-product-api/detail-10-m-20260830T115956Z-0000000a.json";
import detail11Json from "../../public/data/gate-002-product-api/detail-11-m-20260830T115955Z-0000000b.json";
import emptyListJson from "../../public/data/gate-002-product-api/empty-list.json";
import invalidFilterJson from "../../public/data/gate-002-product-api/invalid-filter.json";
import listJson from "../../public/data/gate-002-product-api/list.json";
import paginationProbeJson from "../../public/data/gate-002-product-api/pagination-probe.json";
import statusFilterJson from "../../public/data/gate-002-product-api/status-filter.json";
import targetFilterJson from "../../public/data/gate-002-product-api/target-filter.json";

// ---------------------------------------------------------------------------
// Les schémas ci-dessous épousent les captures gate-002-product-api, copiées
// octet pour octet depuis `docs/coordination/captures/gate-002-product-api/`
// (main @ 5f5e09d6) vers `public/data/gate-002-product-api/`.
// Rien n'est ajouté : un champ absent des captures reste absent du type
// (`.optional()`), jamais un zéro ni une chaîne fabriquées.
// Contrats exercés : agnt.history.v1, agnt.timeline.v1, agnt.execution-status.v1.
// ---------------------------------------------------------------------------

/* ---------- agnt.history.v1 — côté liste ---------- */

// Vocabulaire fermé des statuts : énoncé par l'API elle-même dans sa réponse
// HTTP 400 (invalid-filter.json : « admis : en_file, en_cours, termine,
// refuse, erreur, inconnu »). Ce n'est pas une supposition du front.
export const Status = z.enum(["en_file", "en_cours", "termine", "refuse", "erreur", "inconnu"]);
export type MissionStatus = z.infer<typeof Status>;

export const Target = z.object({ type: z.string(), display_name: z.string() });
export type Target = z.infer<typeof Target>;

// `by_severity` est observé vide ({} sur « zéro prouvé ») ou sévérités -> effectif.
export const FindingsSummary = z.object({
  total: z.number(),
  by_severity: z.record(z.string(), z.number()),
});

// Dans les détails comme dans les listes, run_id / started_at / completed_at /
// duration_ms / findings_summary / clusters_count / artifacts sont absents sur
// certaines missions (refus pré-run, arrêt avant exécution) : optionnels.
export const Mission = z.object({
  mission_id: z.string(),
  detail_href: z.string(),
  request: z.object({ title: z.string() }),
  target: Target,
  status: Status,
  created_at: z.string(),
  updated_at: z.string(),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  duration_ms: z.number().optional(),
  run_id: z.string().optional(),
  findings_summary: FindingsSummary.optional(),
  clusters_count: z.number().optional(),
  artifacts: z.record(z.string(), z.boolean()).optional(),
});
export type Mission = z.infer<typeof Mission>;

// pagination-probe.json (limit=1) publie un next_cursor non nul ; les autres
// captures de liste ont next_cursor: null. Jamais de valeur implicite.
export const Page = z.object({ limit: z.number(), next_cursor: z.string().nullable() });
export type Page = z.infer<typeof Page>;

export const HistoryList = z.object({
  schema_version: z.literal("agnt.history.v1"),
  items: z.array(Mission),
  page: Page,
});
export type HistoryList = z.infer<typeof HistoryList>;

// Corps d'erreur observé dans invalid-filter.json (HTTP 400) : { error: { code, message } }.
export const ApiErrorBody = z.object({ error: z.object({ code: z.string(), message: z.string() }) });
export type ApiErrorBody = z.infer<typeof ApiErrorBody>;

/* ---------- agnt.execution-status.v1 ---------- */

// Chaque dimension de décision est observée sous la forme { value, proof }
// avec un reason_code optionnel (apparaît sur les chemins refus / binaire
// absent / échec / deadline / annulation / incomplet).
// Les tokens de value/proof ne sont PAS énumérés : le front affiche le token
// capturé tel quel, y compris un jeton jamais vu ici.
export const DecisionBlock = z.object({
  value: z.string(),
  proof: z.string(),
  reason_code: z.string().optional(),
});
export type DecisionBlock = z.infer<typeof DecisionBlock>;

// Bloc execution : seuls blocs observés avec invocation/output (« oui|non »,
// « exploitable|non_exploitable ») en plus de value/proof.
export const ExecutionBlock = DecisionBlock.extend({
  invocation: z.string(),
  output: z.string(),
});
export type ExecutionBlock = z.infer<typeof ExecutionBlock>;

// Bloc detection : findings_count/analyzed_targets n'existent que là où la
// détection est évaluée (rien_trouve / findings_presents). Sur non_evalue /
// inconnu, ils sont absents — le front n'affiche donc jamais 0 par défaut.
export const DetectionBlock = DecisionBlock.extend({
  findings_count: z.number().optional(),
  analyzed_targets: z.number().optional(),
});
export type DetectionBlock = z.infer<typeof DetectionBlock>;

export const Completeness = z.object({
  state: z.string(),
  limitations: z.array(z.string()),
  missing: z.array(z.string()),
});
export type Completeness = z.infer<typeof Completeness>;

export const ExecutionStatus = z.object({
  schema_version: z.literal("agnt.execution-status.v1"),
  provider_id: z.string(),
  display_name: z.string(),
  capability_id: z.string().optional(),
  applicability: DecisionBlock,
  selection: DecisionBlock,
  condition: DecisionBlock,
  authorization: DecisionBlock,
  availability: DecisionBlock,
  execution: ExecutionBlock,
  detection: DetectionBlock,
  completeness: Completeness,
  // Provenance projetée : observée uniquement sur la mission « mcp »
  // (allowlist de champs, aucune clé hostile). Forme libre côté valeurs :
  // le front l'affiche brute, il ne l'interprète pas.
  provenance: z.record(z.string(), z.unknown()).optional(),
});
export type ExecutionStatus = z.infer<typeof ExecutionStatus>;

/* ---------- findings normalisés ---------- */

// Observés sur les 3 findings des captures : les cinq blocs sont présents,
// location.line est un numéro, severity porte « origine » (et non origin).
export const Finding = z.object({
  evidence: z.object({ title: z.string(), description: z.string() }),
  identity: z.object({ canonical_rule_id: z.string(), fingerprint: z.string() }),
  location: z.object({ asset: z.string(), file: z.string(), line: z.number() }),
  severity: z.object({ value: z.string(), origine: z.string() }),
  source: z.object({ tool: z.string() }),
});
export type Finding = z.infer<typeof Finding>;

export const Clusters = z.object({
  // members/non_regroupe sont des tableaux vides dans les captures observées ;
  // typés en inconnu, le front ne devine pas leur forme.
  clusters: z.array(z.object({ cluster_id: z.string(), members: z.array(z.unknown()) })),
  non_regroupe: z.array(z.unknown()),
  stats: z.record(z.string(), z.unknown()),
});
export type Clusters = z.infer<typeof Clusters>;

/* ---------- agnt.timeline.v1 — journal projeté ---------- */

export const TimelineEvent = z.object({
  event_id: z.string(),
  position: z.number(),
  kind: z.string(),
  category: z.string(),
  consequence: z.string(),
  data_state: z.string(),
  visibility: z.string(),
  safe_summary: z.string(),
  limitations: z.array(z.string()),
  references: z.record(z.string(), z.string()),
  source: z.object({ kind: z.string(), sequence: z.number(), source_kind: z.string().optional() }),
  time: z.object({ state: z.string(), timestamp: z.string() }),
});
export type TimelineEvent = z.infer<typeof TimelineEvent>;

export const Timeline = z.object({
  schema_version: z.literal("agnt.timeline.v1"),
  state: z.string(),
  ordering: z.string(),
  returned_events: z.number(),
  total_events: z.number(),
  truncated: z.boolean(),
  next_cursor: z.string().nullable(),
  limitations: z.array(z.string()),
  events: z.array(TimelineEvent),
});
export type Timeline = z.infer<typeof Timeline>;

// data.events : journal legacy, compteur indépendant de data.timeline
// (le gate interdit toute fusion des deux — le front n'en fait pas la somme).
export const LegacyEvent = z.object({
  kind: z.string(),
  safe_message: z.string(),
  sequence: z.number(),
  timestamp: z.string(),
});
export type LegacyEvent = z.infer<typeof LegacyEvent>;

/* ---------- agnt.history.v1 — côté détail ---------- */

export const MissionRequest = z.object({ original: z.string(), canonical: z.string() });

export const Intent = z.object({
  type: z.string(),
  seq: z.number(),
  ts: z.string(),
  statut: z.string(),
  capabilities: z.array(z.string()),
});

// Sur la seule capture portant un plan, cree_le/moteur_intent/request_id/
// requete_canonique existent avec la valeur null : null lisible, pas un champ
// retiré. selection est observé {} ; steps portent la sélection réelle.
export const Plan = z.object({
  plan_id: z.string(),
  cree_le: z.string().nullable(),
  moteur_intent: z.string().nullable(),
  request_id: z.string().nullable(),
  requete_canonique: z.string().nullable(),
  selection: z.record(z.string(), z.unknown()),
  steps: z.array(
    z.object({ capability: z.string(), provider: z.string(), risque: z.string(), sorties: z.array(z.unknown()) })
  ),
});
export type Plan = z.infer<typeof Plan>;

export const Report = z.object({
  available: z.boolean(),
  content: z.string().optional(),
  format: z.string().optional(),
});

export const MissionData = z.object({
  request: MissionRequest,
  intent: Intent.optional(),
  plan: Plan.optional(),
  findings: z.array(Finding).optional(),
  clusters: Clusters.optional(),
  report: Report.optional(),
  coverage: z.record(z.string(), z.unknown()).optional(),
  execution_status_schema: z.literal("agnt.execution-status.v1"),
  executions: z.array(ExecutionStatus),
  events: z.array(LegacyEvent),
  timeline: Timeline,
});
export type MissionData = z.infer<typeof MissionData>;

export const MissionDetail = z.object({
  schema_version: z.literal("agnt.history.v1"),
  mission: Mission,
  // missing_artifacts est TOUJOURS présent côté détail (vide quand tout est là).
  missing_artifacts: z.array(z.string()),
  data: MissionData,
});
export type MissionDetail = z.infer<typeof MissionDetail>;

/* ---------- manifeste de capture + chargement typé ---------- */

export const CaptureResponse = z.object({
  role: z.string(),
  path: z.string(),
  status: z.number(),
  body_file: z.string(),
});
export type CaptureResponse = z.infer<typeof CaptureResponse>;

export const CaptureManifest = z.object({
  capture: z.string(),
  submission_id: z.string(),
  responses: z.array(CaptureResponse),
});
export type CaptureManifest = z.infer<typeof CaptureManifest>;

export const MANIFEST = CaptureManifest.parse(captureManifestJson);

const RAW_BODIES: Record<string, unknown> = {
  "list.json": listJson,
  "pagination-probe.json": paginationProbeJson,
  "status-filter.json": statusFilterJson,
  "target-filter.json": targetFilterJson,
  "empty-list.json": emptyListJson,
  "invalid-filter.json": invalidFilterJson,
  "detail-01-m-20260830T120005Z-00000001.json": detail01Json,
  "detail-02-m-20260830T120004Z-00000002.json": detail02Json,
  "detail-03-m-20260830T120003Z-00000003.json": detail03Json,
  "detail-04-m-20260830T120002Z-00000004.json": detail04Json,
  "detail-05-m-20260830T120001Z-00000005.json": detail05Json,
  "detail-06-m-20260830T120000Z-00000006.json": detail06Json,
  "detail-07-m-20260830T115959Z-00000007.json": detail07Json,
  "detail-08-m-20260830T115958Z-00000008.json": detail08Json,
  "detail-09-m-20260830T115957Z-00000009.json": detail09Json,
  "detail-10-m-20260830T115956Z-0000000a.json": detail10Json,
  "detail-11-m-20260830T115955Z-0000000b.json": detail11Json,
};

export type CaptureBody = HistoryList | ApiErrorBody | MissionDetail;

export interface CapturedResponse extends CaptureResponse {
  body: CaptureBody;
}

function parseCaptureBody(role: string, bodyFile: string, status: number): CaptureBody {
  const raw = RAW_BODIES[bodyFile];
  if (raw === undefined) {
    // Un corps cité par le manifeste et absent du dossier = dérive de copie,
    // pas un cas d'usage : on échoue bruyamment, on ne remplace pas par du vide.
    throw new Error(`capture manquante pour ${bodyFile} (rôle « ${role} »)`);
  }
  if (role === "detail") return MissionDetail.parse(raw);
  if (status >= 400) return ApiErrorBody.parse(raw);
  return HistoryList.parse(raw);
}

// Registre des 17 réponses, dans l'ordre du manifeste, chacune typée par son
// contrat et étiquetée de son URL + statut HTTP réels.
export const CAPTURES: CapturedResponse[] = MANIFEST.responses.map((entry) => ({
  ...entry,
  body: parseCaptureBody(entry.role, entry.body_file, entry.status),
}));

export function isHistoryList(body: CaptureBody): body is HistoryList {
  return "items" in body;
}
export function isApiError(body: CaptureBody): body is ApiErrorBody {
  return "error" in body;
}
export function isMissionDetail(body: CaptureBody): body is MissionDetail {
  return "mission" in body;
}

/** Liste principale capturée (GET /api/missions?limit=25). */
export function getHistory(): HistoryList {
  const entry = CAPTURES.find((c) => c.role === "list");
  if (!entry || !isHistoryList(entry.body)) throw new Error("capture « list » absente du manifeste");
  return entry.body;
}

/** Détail capturé d'une mission, par mission_id (la réponse réelle du même id). */
export function getDetail(missionId: string): MissionDetail | undefined {
  for (const entry of CAPTURES) {
    if (entry.role === "detail" && isMissionDetail(entry.body) && entry.body.mission.mission_id === missionId) {
      return entry.body;
    }
  }
  return undefined;
}
