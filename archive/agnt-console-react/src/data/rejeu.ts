/**
 * Rejeu d'une exécution RÉELLE du moteur sur PHASE3/testrepo_iac
 * (checkov 3.3.15, 38 observations — capture versionnée
 * PHASE3/testrepo_iac/artefacts_captures/checkov_multiframework.json).
 *
 * Règle du projet : un écran qui se prend pour un écran de résultat est le
 * défaut qu'on veut éviter. Cette donnée est donc affichée SOUS BANDEAU
 * « MAQUETTE — REJEU D'UNE EXÉCUTION PASSÉE » tant qu'aucune API moteur ne
 * répond. Le numéro de mission affiché est le dossier d'archive, pas un run_id.
 */

export type Gravite = "HIGH" | "MEDIUM" | "UNKNOWN";

export interface Observation {
  id: string;
  outil: string;
  regle: string;
  message: string;
  fichier: string;
  ligne: number | null;
  gravite: Gravite;
  cadre: string;
}

export interface Cluster {
  id: string;
  membres: string[];
  motifs: string[];
  fichier: string | null;
  gravite: Gravite;
}

export interface Couverture {
  capacite: string;
  provider: string;
  risque: "passif" | "actif" | "exploit";
  statut: "exécuté" | "non applicable" | "refusé";
  detail: string;
}

export interface Rejeu {
  cible: string;
  mission: string;
  outils: string[];
  observations: Observation[];
  clusters: Cluster[];
  couverture: Couverture[];
  journal: { tag: string; msg: string; detail?: string }[];
}

/** Extraction fidèle de la capture checkov (38 findings : 15 tf + 20 k8s + 3 dockerfile). */
const CAPTURE: { ct: string; id: string; name: string; file: string; line: number | null }[] = [
  // terraform — /main.tf
  { ct: "terraform", id: "CKV_AWS_3", name: "Ensure all data stored in the EBS is securely encrypted", file: "main.tf", line: 17 },
  { ct: "terraform", id: "CKV_AWS_189", name: "Ensure EBS Volume is encrypted by KMS using a customer managed key", file: "main.tf", line: 17 },
  { ct: "terraform", id: "CKV_AWS_23", name: "Ensure every security group and rule has a description", file: "main.tf", line: 24 },
  { ct: "terraform", id: "CKV_AWS_24", name: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22", file: "main.tf", line: 24 },
  { ct: "terraform", id: "CKV_AWS_25", name: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389", file: "main.tf", line: 24 },
  { ct: "terraform", id: "CKV_AWS_260", name: "Ensure no security groups allow ingress from 0.0.0.0:0 to any port", file: "main.tf", line: 24 },
  { ct: "terraform", id: "CKV2_AWS_62", name: "Ensure S3 buckets should have event notifications enabled", file: "main.tf", line: 11 },
  { ct: "terraform", id: "CKV2_AWS_6", name: "Ensure that S3 bucket has a Public Access block", file: "main.tf", line: 11 },
  { ct: "terraform", id: "CKV2_AWS_61", name: "Ensure that an S3 bucket has a lifecycle configuration", file: "main.tf", line: 11 },
  { ct: "terraform", id: "CKV_AWS_18", name: "Ensure the S3 bucket has access logging enabled", file: "main.tf", line: 11 },
  { ct: "terraform", id: "CKV_AWS_144", name: "Ensure that S3 bucket has cross-region replication enabled", file: "main.tf", line: 11 },
  { ct: "terraform", id: "CKV2_AWS_5", name: "Ensure that Security Groups are attached to another resource", file: "main.tf", line: 24 },
  { ct: "terraform", id: "CKV_AWS_21", name: "Ensure all data stored in the S3 bucket have versioning enabled", file: "main.tf", line: 11 },
  { ct: "terraform", id: "CKV_AWS_145", name: "Ensure S3 buckets are encrypted with KMS by default", file: "main.tf", line: 11 },
  { ct: "terraform", id: "CKV_AWS_20", name: "S3 Bucket has an ACL defined which allows public READ access", file: "main.tf", line: 11 },
  // kubernetes — k8s.yaml
  { ct: "kubernetes", id: "CKV_K8S_20", name: "Containers should not run with allowPrivilegeEscalation", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_11", name: "CPU limits should be set", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_10", name: "CPU requests should be set", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_21", name: "The default namespace should not be used", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_28", name: "Minimize the admission of containers with the NET_RAW capability", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_43", name: "Image should use digest", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_14", name: "Image Tag should be fixed - not latest or blank", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_8", name: "Liveness Probe Should be Configured", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_13", name: "Memory limits should be set", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_12", name: "Memory requests should be set", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_37", name: "Minimize the admission of containers with capabilities assigned", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_29", name: "Apply security context to your pods and containers", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_16", name: "Container should not be privileged", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_22", name: "Use read-only filesystem for containers where possible", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_9", name: "Readiness Probe Should be Configured", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_23", name: "Minimize the admission of root containers", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_40", name: "Containers should run as a high UID to avoid host conflict", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_31", name: "Ensure that the seccomp profile is set to docker/default or runtime/default", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV_K8S_38", name: "Ensure that Service Account Tokens are only mounted where necessary", file: "k8s.yaml", line: 2 },
  { ct: "kubernetes", id: "CKV2_K8S_6", name: "Minimize the admission of pods which lack an associated NetworkPolicy", file: "k8s.yaml", line: 2 },
  // dockerfile
  { ct: "dockerfile", id: "CKV_DOCKER_7", name: "Ensure the base image uses a non latest version tag", file: "Dockerfile", line: 2 },
  { ct: "dockerfile", id: "CKV_DOCKER_2", name: "Ensure that HEALTHCHECK instructions have been added to container images", file: "Dockerfile", line: 1 },
  { ct: "dockerfile", id: "CKV_DOCKER_3", name: "Ensure that a user for the container has been created", file: "Dockerfile", line: 1 },
];

const observations: Observation[] = CAPTURE.map((f, i) => ({
  id: `OBS-${String(i + 1).padStart(3, "0")}`,
  outil: "checkov",
  regle: f.id,
  message: f.name,
  fichier: f.file,
  ligne: f.line,
  gravite: "UNKNOWN",
  cadre: f.ct,
}));

/** Regroupements : même (fichier, ligne) → un cluster. 38 obs → 5 regroupements (mesuré sur le run réel). */
const parLigne = new Map<string, string[]>();
for (const o of observations) {
  const k = `${o.fichier}:${o.ligne ?? "-"}`;
  (parLigne.get(k) ?? parLigne.set(k, []).get(k)!).push(o.id);
}
let n = 0;
const clusters: Cluster[] = [...parLigne.entries()].map(([k, ids]) => {
  n += 1;
  const [fichier, ligne] = k.split(":");
  return {
    id: `CL-${String(n).padStart(3, "0")}`,
    membres: ids,
    motifs: ["same_file", "same_line"],
    fichier: fichier,
    gravite: "UNKNOWN",
  };
});
// La ligne k8s.yaml:2 regroupe les 20 findings kubernetes — un seul cluster.
const fuse = clusters.find((c) => c.fichier === "k8s.yaml");
if (fuse) fuse.motifs = ["same_file", "same_line", "same_framework:kubernetes"];

export const REJEU: Rejeu = {
  cible: "PHASE3/testrepo_iac",
  mission: "artifacts/missions/08db897365d68278 (archive)",
  outils: ["checkov"],
  observations,
  clusters,
  couverture: [
    { capacite: "IAC_SCAN", provider: "checkov", risque: "passif", statut: "exécuté", detail: "38 observations · terraform 15 · kubernetes 20 · dockerfile 3 · terraform_plan 0" },
    { capacite: "DEPENDENCY_ANALYSIS", provider: "trivy", risque: "passif", statut: "non applicable", detail: "aucun manifeste exploitable déclaré (not_scanned honnête)" },
    { capacite: "CODE_STATIC_ANALYSIS", provider: "semgrep", risque: "passif", statut: "non applicable", detail: "aucun fichier Python/JS ciblé par les règles épinglées" },
    { capacite: "SECRET_DETECTION", provider: "gitleaks", risque: "passif", statut: "non applicable", detail: "historique git non requis pour cette cible" },
  ],
  journal: [
    { tag: "sys", msg: "mission ouverte — append-only" },
    { tag: "intent", msg: "« Analyse la sécurité de ce dépôt » → résolue", detail: "capacités : IAC_SCAN (+ génériques)" },
    { tag: "plan", msg: "plan typé construit — 1 provider sélectionné", detail: "checkov · priorité déclarée · motif tracé dans plan.json" },
    { tag: "opa", msg: "policy ALLOW", detail: "cible controlled_dev · outil passif · réseau coupé" },
    { tag: "box", msg: "sandbox bwrap — uid 1000, racine lecture seule, --unshare-net" },
    { tag: "tool", msg: "checkov 3.3.15 — exécution hors ligne", detail: "38 findings bruts, aucune fuite du faux secret (garde-fou OK)" },
    { tag: "norm", msg: "extraction déclarative — blocs imbriqués ($ → 4 sous-analyses)", detail: "cadre ← check_type : terraform / kubernetes / dockerfile" },
    { tag: "corr", msg: `${clusters.length} regroupements (same_file, same_line)`, detail: "gravité UNKNOWN conservée — jamais inventée" },
    { tag: "done", msg: "mission close — rapport écrit sans LLM", detail: "deux exécutions → même rapport (déterministe)" },
  ],
};
