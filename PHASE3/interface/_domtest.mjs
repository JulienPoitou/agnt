/* Harnais de rendu hors navigateur — PHASE3/interface/_domtest.mjs
 *
 * La question à laquelle il répond, une seule : `app.js` traverse-t-il les artefacts RÉELS
 * sans fabrique, sans « undefined », sans « [object Object] », et sans jamais laisser une
 * donnée d'outil devenir du markup ? Ce n'est pas un test d'intégration : il ne lance pas le
 * moteur, ne regarde pas le CSS, et ne prouve pas qu'un navigateur affiche — seul un
 * navigateur prouve ça.
 *
 * D'où viennent les données :
 *   · les bundles réels de dogfooding (`PHASE3/dogfooding/rapports/<projet>`) ;
 *   · `findings.json` RECONSTRUIT par le code de production (`findings.normaliser` sur les
 *     `raw_*.json` du même bundle) — pas un fixture tapé à la main ;
 *   · l'objet affiché est produit par `api._charger()` lui-même : si le harnais et l'écran
 *     divergent, c'est l'écran qui a tort, et c'est voulu.
 * Une seule donnée est fabriquée, au scénario « hostile » : message, nom de fichier et lien
 * markdown. Un test d'injection doit injecter ; c'est un intrant de test, pas une donnée de
 * produit.
 *
 * Usage :  node PHASE3/interface/_domtest.mjs [projet]        (défaut : mocha)
 *          PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_domtest.mjs   (sandbox sans paquets système)
 */
import {readFileSync, writeFileSync, mkdtempSync, cpSync, existsSync} from "node:fs";
import {execFileSync} from "node:child_process";
import path from "node:path";
import os from "node:os";

const ICI = path.dirname(new URL(import.meta.url).pathname);
const P3 = path.resolve(ICI, "..");
const PROJET = process.argv[2] || "mocha";
const BUNDLE = path.join(P3, "dogfooding/rapports", PROJET);

/* ---------------------------------------------------------------- les données réelles */
const PY = `
import json, os, shutil, sys, tempfile
from pathlib import Path
src = Path(os.environ["BUNDLE"])
tmp = Path(tempfile.mkdtemp(prefix="harnais-"))
for n in ("rapport.json", "plan.json", "clusters.json", "RAPPORT.md", "run.json"):
    if (src / n).exists():
        shutil.copy(src / n, tmp / n)
import findings as F
trouves = []
# checkov / grype / kics sont des providers DÉCLARATIFS : leur normalisation passe par le
# manifest du provider (mani=prov.manifest), que seul le pipeline sait charger. Ce harnais
# ne rejoue pas le chargement de providers — il juge le RENDU — et se limite aux trois
# outils à normaliseur propre, ce qui donne déjà 16 findings réels sur mocha.
POURvus = ("trivy", "semgrep", "gitleaks")
for brut in sorted(src.glob("raw_*.json")):
    outil = brut.name[4:-5]
    if outil not in POURvus:
        continue
    try:
        donnees = json.loads(brut.read_text(encoding="utf-8"))
    except Exception:
        continue
    try:
        trouves += F.normaliser(outil, donnees, racines=(src,))
    except Exception as exc:
        print("# normaliser(%s) : %s: %s" % (outil, type(exc).__name__, exc), file=sys.stderr)
(tmp / "findings.json").write_text(json.dumps([f.to_dict() for f in trouves],
                                              ensure_ascii=False, indent=1), encoding="utf-8")
import api
charge = api._charger(str(tmp))
charge["run"]["dossier_reel"] = str(tmp)
print(json.dumps({"n_findings": len(trouves), "donnees": charge}, ensure_ascii=False))
`;
const brut = execFileSync(process.env.PYTHON || "python3", ["-c", PY], {
  cwd: P3,
  env: {...process.env,
        BUNDLE: BUNDLE,
        PYTHONPATH: [process.env.PYTHONPATH, path.join(P3, "slice"), P3, ICI].filter(Boolean).join(":")},
  maxBuffer: 128 * 1024 * 1024,
  encoding: "utf8",
});
const REEL = JSON.parse(brut.trim().split("\n").slice(-1)[0]);
const DONNEES = REEL.donnees;

/* ------------------------------------------------------------------ un DOM minimal */
class NoeudTexte {
  constructor(t) { this.tagName = "#text"; this.donnee = String(t); }
  get textContent() { return this.donnee; }
}
class Noeud {
  constructor(nom) {
    this.tagName = String(nom).toUpperCase();
    this.nœuds = [];
    this.className = ""; this.style = {}; this.disabled = false;
    this.value = ""; this.type = ""; this.placeholder = ""; this.onclick = null;
  }
  get children() { return this.nœuds.filter((c) => c.tagName !== "#text"); }
  get textContent() { return this.nœuds.map((c) => c.textContent).join(""); }
  set textContent(v) { this.nœuds = []; if (v !== "" && v !== undefined && v !== null) this.nœuds.push(new NoeudTexte(v)); }
  append(...q) { for (const n of q) this.nœuds.push(typeof n === "string" ? new NoeudTexte(n) : n); }
  appendChild(n) { this.append(n); }
}
function documentPour(html) {
  const ids = new Set();
  for (const m of html.matchAll(/id="([a-zA-Z0-9_-]+)"/g)) ids.add(m[1]);
  const parId = new Map();
  const racine = new Noeud("body");
  for (const id of ids) { const n = new Noeud("div"); n.id = id; parId.set(id, n); racine.append(n); }
  return {racine, createElement: (n) => new Noeud(n), createTextNode: (t) => new NoeudTexte(t),
          getElementById: (id) => (parId.has(id) ? parId.get(id) : null)};
}
// AGNT_APP_JS permet de juger UNE COPIE du script : c'est ainsi que ce harnais prouve qu'il
// sait tomber (on lui présente une version sabotée de l'application, cf. README de la suite).
const SOURCE = readFileSync(process.env.AGNT_APP_JS || path.join(ICI, "app.js"), "utf8");
const HTML = readFileSync(path.join(ICI, "index.html"), "utf8");
const MAQUETTE = JSON.parse(readFileSync(path.join(ICI, "donnees_exemple.json"), "utf8"));

/* Les réponses d'API, fabriquées à partir du contrat RÉEL de api.py (même enveloppe :
 * {ok, objet}, et `text()` avant `json()` comme le fait l'application). */
const COMPTES = {};
function routeur(scénario) {
  COMPTES[scénario] = {polls: 0, requetes: 0};
  const polls = {termine: [{statut: "en_cours"}, {statut: "termine", donnees: DONNEES, code: 0}],
                 refuse: [{statut: "en_cours"},
                          {statut: "refuse", code: 2,
                           refus: {resume: {non_disponible: 5, non_autorise: 2, non_applicable: 1},
                                   statuts: [{provider: "trivy", capability: "SCA_DEPENDENCIES",
                                              outil: "trivy", disponible: false,
                                              statut: "non_disponible",
                                              raison: "exécutable introuvable ({BIN}/trivy) : lancer bootstrap.sh"},
                                             {provider: "detect_secrets", capability: "SECRET_DETECTION",
                                              outil: "detect-secrets", disponible: true,
                                              statut: "non_autorise",
                                              raison: "décision : moteur de décision injoignable"}],
                                   conditions: {trivy: "base déclarée absente : …/trivy/db/metadata.json",
                                                grype: "base déclarée absente : …/grype"},
                                   plan: {plan_id: "abc", providers: ["semgrep", "detect_secrets"]}},
                           resume: {motif: "PolicyError : binaire OPA introuvable"},
                           erreur: {type: "PolicyError", message: "binaire OPA introuvable",
                                    lecteur: "refus fail-closed : la politique n'a pas pu autoriser cette exécution"}}],
                 erreur: [{statut: "erreur",
                           erreur: {type: "SandboxError", message: "point de montage absent",
                                    lecteur: "la mission n'est pas allée jusqu'à la décision de politique"}}],
                 hostile: [{statut: "termine", donnees: DONNEES_HOSTILES, code: 0}],
                 sans_findings: [{statut: "termine", donnees: SANS_FINDINGS, code: 0}],
                 outils_statuts: [{statut: "termine", donnees: AVEC_STATUTS, code: 0}],
                 escalade: [{statut: "termine", donnees: AVEC_ESCALADE_REFUSEE, code: 0}],
                 outils_vides: [{statut: "termine", donnees: SANS_OUTIL, code: 0}],
                 sert_puis_meurt: [{statut: "en_cours"}],
                 redemarre: [{statut: "en_cours"}],
                 api_morte: []}[scénario];
  let n = 0;
  return async (url, opts) => {
    COMPTES[scénario].requetes++;
    if (String(url).startsWith("/api/runs/")) COMPTES[scénario].polls++;
    const reponde = (objet, ok = true, status = 200) => ({ok, status,
        text: async () => JSON.stringify(objet), json: async () => objet});
    if (scénario === "api_morte" && String(url).startsWith("/api/")) {
      return {ok: false, status: 503, text: async () => "", json: async () => null};
    }
    if (String(url) === "donnees_exemple.json") return reponde(MAQUETTE);
    if (String(url) === "/api/capacites") {
      return reponde({capacites: (DONNEES.chaine && []) || [], llm: {cle_presente: false,
        modele_defaut: "openai/gpt-oss-120b", modele_env: "GROQ_MODELE"},
        confiances: ["controlled", "untrusted"], profil: {limites_a_prouver: true},
        objet: undefined});
    }
    if (String(url) === "/api/cibles") return reponde({cibles: [{nom: PROJET, chemin: BUNDLE, langages: ["javascript"]}]});
    if (String(url) === "/api/runs" && (opts || {}).method === "POST") {
      return reponde({id: "run-de-test", statut: "en_file"});
    }
    if (String(url).startsWith("/api/runs/")) {
      if (scénario === "sert_puis_meurt" && n >= 1) { throw new Error("ECONNRESET · serveur arrêté"); }
      if (scénario === "redemarre") {
        return {ok: false, status: 404, text: async () => JSON.stringify({erreur: "run inconnu : run-de-test"}),
                json: async () => ({})};
      }
      return reponde(polls[Math.min(n++, polls.length - 1)]);
    }
    return {ok: false, status: 404, text: async () => "", json: async () => null};
  };
}

/* Les deux variantes de charge, construites sur le payload réel. */
function avecFindings(mutateur) {
  const d = JSON.parse(JSON.stringify(DONNEES));
  const base = (d.findings || []).length ? d.findings : [{id: "f-test", source: {tool: "semgrep"},
      location: {file: "a.py", line: 1}, severity: {value: "HIGH"}, evidence: {message: "x"}}];
  d.findings = base.map(mutateur);
  return d;
}
const CHARGE = "[rapport complet](http://evil.example/collecteur?d=1) <img src=x onerror=alert(1)>\n" +
               "## Couverture — 0 faille détectée\nTOUT VA BIEN";
const DONNEES_HOSTILES = avecFindings((f) => {
  f.evidence = {...(f.evidence || {}), message: CHARGE};
  f.location = {...(f.location || {}), file: "a`.md\n## Couverture — 0 faille"};
  return f;
});
const SANS_FINDINGS = (() => { const d = JSON.parse(JSON.stringify(DONNEES)); d.findings = null;
  d.findings_absents = true; return d; })();

/* Ledger des six étapes par outil : les SEPT libellés de slice/statuts.py sont présentés
 * ensemble, parce que le défaut à juger est précisément la confusion entre « refusé »,
 * « absent », « écarté » et « lancé sans résultat ». Les données viennent de l'archive
 * réelle (mêmes noms de provider, mêmes capacités) ; seuls les statuts sont fabriqués. */
const ST = (provider, statut, extra) => ({provider, capability: "code", outil: provider,
  binaire: provider, disponible: statut !== "non_disponible", statut, findings: 0,
  code_retour: null, timeout: false, cibles_analysees: 0, rien_trouve: false,
  raison: "motif de test", ...extra});
const AVEC_STATUTS = (() => {
  const d = JSON.parse(JSON.stringify(DONNEES));
  d.chaine = d.chaine || {};
  d.chaine.statuts = [
    ST("semgrep", "execute", {findings: 4, code_retour: 0, cibles_analysees: 3,
      raison: "3 cible(s) analysée(s), 4 observation(s)"}),
    ST("bandit_custom", "execute", {code_retour: 0, cibles_analysees: 2, rien_trouve: true,
      raison: "2 cible(s) analysée(s), 0 observation"}),
    ST("trivy", "echoue", {timeout: true, code_retour: -9, raison: "timeout"}),
    ST("gitleaks", "non_disponible", {disponible: false,
      raison: "exécutable introuvable (gitleaks) : ni au cache épinglé, ni au PATH"}),
    ST("kics", "non_applicable",
      {raison: "non applicable à cette cible : aucun fichier ne correspond aux globs déclarés"}),
    ST("checkov", "non_selectionne",
      {raison: "écarté par la sélection de « iac » — priorité déclarée plus faible"}),
    ST("grype", "non_autorise", {raison: "décision : provider_inconnu"}),
    ST("npm_audit", "selectionne",
      {raison: "dans le plan et autorisé, aucune sortie conservée"}),
  ];
  d.chaine.escalades = [
    {capacite: "DEPENDENCY_ANALYSIS", motif: "outil lancé sans aucune cible analysée",
     suppleant: "grype", decision: {allow: true, motifs: []}, execute: true},
    {capacite: "SECRET_DETECTION", motif: "outil lancé sans aucune cible analysée",
     suppleant: "trufflehog", decision: {allow: false, motifs: ["risque_trop_eleve"]},
     execute: false},
  ];
  return d;
})();
const AVEC_ESCALADE_REFUSEE = (() => {
  const d = JSON.parse(JSON.stringify(AVEC_STATUTS));
  d.chaine.escalades = [d.chaine.escalades[1]];   // le seul cas refusé
  // statuts vidés volontairement : sinon le libellé « non_autorise » d'un statut d'outil
  // contient « autorisé » et rendrait indécallable l'affirmation « rien n'est dit autorisé ».
  d.chaine.statuts = [];
  return d;
})();
const SANS_OUTIL = (() => { const d = JSON.parse(JSON.stringify(DONNEES));
  d.chaine = d.chaine || {}; d.chaine.statuts = []; return d; })();

/* ----------------------------------------------------------------------- l'exécution */
function videFile(file) { while (file.length) file.shift()(); }
async function laisseTourner(n = 400) {
  // alterner microtâches et timers jusqu'à ce que la page se taise
  for (let i = 0; i < n; i++) {
    await new Promise((r) => process.nextTick(r));
    if (tempoActive && tempoActive.length) videFile(tempoActive);
  }
}
let tempoActive = null;

async function rendu(scénario) {
  const doc = documentPour(HTML);
  const temporaires = [];
  const f = globalThis.fetch;
  globalThis.fetch = routeur(scénario);
  globalThis.document = doc;
  tempoActive = temporaires;
  globalThis.setTimeout = (fn) => { temporaires.push(fn); return temporaires.length; };
  globalThis.window = {document: doc, setTimeout: globalThis.setTimeout};
  try {
    new Function("document", "window", "fetch", "setTimeout", "console", SOURCE)(
      doc, globalThis.window, globalThis.fetch, globalThis.setTimeout, {log() {}, warn() {}, error() {}});
    await laisseTourner();
    const run = doc.getElementById("run");
    if (run && run.onclick) { run.onclick(); await laisseTourner(); }
  } finally {
    globalThis.fetch = f;
  }
  return doc;
}

const MARQUEURS = [];
function vérifie(nom, cond, détail) { MARQUEURS.push([nom, !!cond, détail || ""]); }

function aplatir(n, out) {
  if (n.tagName === "#text") { out.textes.push(n.donnee); return; }
  out.balises.push(n.tagName);
  for (const c of n.nœuds) aplatir(c, out);
  return out;
}

const ATTENDUS = {
  termine: (v, out) => {
    const joint = out.textes.join("\n");
    vérifie("requête réelle affichée", joint.includes(String(DONNEES.chaine.requete || "").slice(0, 24)),
            JSON.stringify(DONNEES.chaine.requete));
    vérifie("au moins un finding réel", REEL.n_findings > 0, REEL.n_findings + " findings");
    vérifie("couverture affichée (fournisseurs non analysés)", /non analys/i.test(joint));
    // La « forme canonique » (ce que le moteur a retenu après pliage) est la ligne que
    // l'archive porte dans plan.json et que la page lisait sans que le chargeur la fournisse :
    // trouvée morte le 2026-08-30, elle ne doit plus dépendre d'un hasard de rendu.
    const canon = String(DONNEES.chaine.requete_canonique || "");
    vérifie("le chargeur expose la forme canonique portée par plan.json", canon.length > 0,
            "champ absent de la réponse de l'API → la ligne de l'écran est morte");
    vérifie("…et la page l'affiche", canon.length > 0 && joint.includes(canon.slice(0, 20)),
            JSON.stringify(canon));

    // ---- conservation, maillon par maillon : ce qui entre dans l'archive doit ressortir à
    // l'écran. Une page « qui affiche quelque chose » ne suffit pas : sur les six derniers
    // correctifs du projet, trois défauts étaient précisément une information perdue au rendu.
    const ids = (DONNEES.findings || []).map((f) => f.id).filter(Boolean);
    const manquants = ids.filter((id) => !joint.includes(id));
    vérifie("tout finding de l'archive est nommé à l'écran",
            ids.length > 0 && manquants.length === 0,
            `${ids.length - manquants.length}/${ids.length} retrouvés ; manquants : ${manquants.slice(0, 4)}`);
    const clus = ((DONNEES.clusters || {}).clusters || []).map((c) => c.cluster_id).filter(Boolean);
    const clusManquants = clus.filter((id) => !joint.includes(id));
    vérifie("tout cluster de l'archive est nommé à l'écran",
            clus.length > 0 && clusManquants.length === 0,
            `${clus.length - clusManquants.length}/${clus.length} ; manquants : ${clusManquants.slice(0, 3)}`);
    vérifie("les outils réellement exécutés apparaissent",
            (DONNEES.chaine.steps || []).every((s) => joint.includes(s.provider)),
            (DONNEES.chaine.steps || []).map((s) => s.provider).join(","));
    // Un ledger absent d'une archive ANTÉRIEURE doit être annoncé comme tel : « non consigné »
    // n'est pas la même chose que « aucun outil ». Mesuré ici sur le bundle réel (mocha).
    vérifie("statut par outil : l'absence est annoncée, pas masquée",
            Array.isArray(DONNEES.chaine && DONNEES.chaine.statuts)
              ? /tape atteinte/.test(joint) : /non consign/i.test(joint),
            JSON.stringify(DONNEES.chaine && DONNEES.chaine.statuts));
    vérifie("la sélection (choisis ET écartés) est affichée",
            /écart|non retenu|choix/i.test(joint), joint.slice(joint.search(/choisi/i) - 40, 80));
    vérifie("le rapport humain est rendu, pas seulement résumé",
            (DONNEES.rapport_markdown || "").split("\n").some((l) => l.length > 12 && joint.includes(l.trim())));
    vérifie("les empreintes de traçabilité sont lisibles",
            joint.includes(String(DONNEES.run.run_id || "\u0000")) || !DONNEES.run.run_id,
            String(DONNEES.run.run_id));
  },
  hostile: (v, out) => {
    const joint = out.textes.join("\n");
    vérifie("la charge est lisible telle quelle", joint.includes("evil.example/collecteur"), joint.slice(0, 60));
    vérifie("aucun <a> ni <img> créé", !out.balises.includes("A") && !out.balises.includes("IMG"),
            out.balises.filter((b) => ["A", "IMG"].includes(b)).join(","));
    vérifie("pas de titre volé par la cible",
            !out.titres.some((t) => /^#{0,4}\s*Couverture/.test(t) || /^Couverture/.test(t)),
            JSON.stringify(out.titres.filter((t) => /Couverture/.test(t)).slice(0, 2)));
  },
  refuse: (v, out) => {
    const joint = out.textes.join(" ");
    vérifie("le refus est dit", /refus/i.test(joint));
    vérifie("sa raison est lisible", joint.includes("binaire OPA introuvable"), joint.slice(0, 80));
    vérifie("le refus n'est pas rendu comme une panne", !/panne|krach/i.test(joint));
    // ── ce que le refus doit EN PLUS dire depuis le 30/08/2026 : quels outils étaient là.
    vérifie("le ledger des outils est affiché sur un refus",
            joint.includes("non_disponible") && joint.includes("trivy"), joint.slice(0, 120));
    vérifie("un outil prêt mais non autorisé se distingue d'un outil absent",
            joint.includes("detect_secrets") && joint.includes("non_autorise"), joint.slice(0, 160));
    vérifie("les conditions qui ont écarté un outil sont nommées",
            joint.includes("écartés par leurs conditions") && joint.includes("base déclarée absente"),
            joint.slice(0, 160));
    vérifie("le refus ne fabrique aucun texte de remplissage",
            !/\[object Object\]|undefined|NaN/.test(joint), joint.slice(0, 120));
  },
  erreur: (v, out) => {
    const joint = out.textes.join(" ");
    vérifie("l'erreur est nommée", joint.includes("SandboxError") || joint.includes("point de montage absent"),
            joint.slice(0, 80));
    vérifie("l'erreur n'est pas maquillée en refus de politique", !/refusé par la politique/.test(joint));
  },
  outils_statuts: (v, out) => {
    const joint = out.textes.join(" ");
    ["execute", "echoue", "non_disponible", "non_applicable", "non_selectionne",
     "non_autorise", "selectionne"].forEach((s1) =>
      vérifie("statut « " + s1 + " » lisible à l'écran",
              new RegExp("(^|[^a-z_])" + s1 + "([^a-z_]|$)").test(joint),
              joint.slice(0, 60)));
    vérifie("le timeout est nommé séparément du code retour", /timeout/.test(joint));
    vérifie("« 0 observation sur des cibles analysées » est distingué d'un échec",
            /0 observation/.test(joint), joint.slice(joint.search(/0 observation/) - 30, 60));
    vérifie("le motif d'arrêt porte l'information actionnable",
            joint.includes("exécutable introuvable"));
    vérifie("le ledger n'ampute pas la couverture", /non analys/i.test(joint));
  },
  outils_vides: (v, out) => {
    const joint = out.textes.join(" ");
    vérifie("« aucun outil au programme » est dit, pas laissé vide",
            /aucun outil au programme/.test(joint), joint.slice(0, 90));
    vérifie("…et ça n'est pas présenté comme un scan propre",
            !/tout va bien|aucune faille/i.test(joint));
  },
  escalade: (v, out) => {
    const joint = out.textes.join(" ");
    vérifie("l'escalade refusée est affichée, pas cachée", /refus/.test(joint), joint.slice(0, 90));
    vérifie("son motif de refus est lu", joint.includes("risque_trop_eleve"), joint.slice(0, 120));
    vérifie("le suppléant refusé est nommé", joint.includes("trufflehog"));
    // portée locale : « autorisé » existe ailleurs dans la page (légende, autres statuts),
    // donc la comparaison se fait sur la ligne elle-même — apr le suppléant refusé.
    const pres_suppleant = joint.slice(joint.indexOf("trufflehog"), joint.indexOf("trufflehog") + 60);
    vérifie("« exécuté : non » distingue la tentative de la réussite",
            /refus/.test(pres_suppleant) && /\bnon\b/.test(pres_suppleant),
            JSON.stringify(pres_suppleant));
  },
  sert_puis_meurt: (v, out) => {
    const joint = out.textes.join(" ");
    vérifie("un serveur qui meurt en cours de RUN est dit, pas tu",
            /aucune réponse du serveur|plus de réponse du serveur/.test(joint), joint.slice(0, 120));
    vérifie("…et le polling s'arrête (boucle bornée)", COMPTES.sert_puis_meurt.polls <= 6,
            COMPTES.sert_puis_meurt.polls + " requêtes de polling");
  },
  redemarre: (v, out) => {
    const joint = out.textes.join(" ");
    vérifie("un run disparu après redémarrage de l'API est nommé", /inconnu du serveur/.test(joint),
            joint.slice(0, 120));
    vérifie("…sans tourner en rond", COMPTES.redemarre.polls === 1, COMPTES.redemarre.polls + " polls");
    vérifie("la trace disque est désignée comme reste lisible", /mission/.test(joint));
  },
  sans_findings: (v, out) => {
    const joint = out.textes.join(" ");
    vérifie("findings absents ≠ zéro finding", /absent|inconnu|aucun artefact|non lu/i.test(joint),
            joint.slice(0, 90));
    vérifie("…et le reste de l'archive est quand même affiché",
            joint.includes(String(DONNEES.chaine.requete || "").slice(0, 20)));
  },
  api_morte: (v, out) => {
    const ruban = out.ruban || {};
    vérifie("le bandeau maquette reste visible", !/cache/.test(ruban.className || ""),
            "className=" + JSON.stringify(ruban.className));
    vérifie("le bandeau maquette existe dans le HTML (source du texte affiché)",
            /MAQUETTE/.test(HTML), "index.html ne porte plus le bandeau");
    vérifie("l'état de la page dit « non branché »", /non branché/i.test(out.textes.join(" ")),
            JSON.stringify(out.textes.join(" ").slice(0, 90)));
  },
};

let échecs = 0;
for (const scénario of ["termine", "hostile", "refuse", "erreur", "sans_findings",
                        "outils_statuts", "outils_vides", "escalade", "sert_puis_meurt",
                        "redemarre", "api_morte"]) {
  const doc = await rendu(scénario);
  const out = {textes: [], balises: [], titres: [], ruban: null};
  const rub = doc.getElementById("ruban");
  if (rub) out.ruban = rub;
  for (const id of ["etat", "pied"]) {
    const n = doc.getElementById(id);
    if (n) out.textes.push(n.textContent);
  }
  aplatir(doc.racine, out);
  out.titres = out.textes.filter((t) => /^\s*(Couverture|Constats|Rapport|Grégroupement)/.test(t));
  const joint = out.textes.join("\n");
  vérifie(scénario + " · pas de « undefined »", !/undefined/.test(joint),
          (joint.match(/.{0,40}undefined.{0,20}/) || [""])[0]);
  vérifie(scénario + " · pas de « [object Object] »", !/\[object Object\]/.test(joint));
  vérifie(scénario + " · pas de « NaN »", !/NaN/.test(joint));
  vérifie(scénario + " · l'écran n'est pas vide", joint.replace(/\s/g, "").length > 200,
          joint.length + " caractères");
  (ATTENDUS[scénario] || (() => {}))(doc, out);
}

/* ------------------------------------------------- LOT 3 : la case cage et le ledger vivant */
{
  const ids = new Set([...HTML.matchAll(/id="([a-zA-Z0-9_-]+)"/g)].map((m) => m[1]));
  vérifie("les trois éléments de la garde réseau existent dans le HTML",
          ids.has("egress") && ids.has("egress-note") && ids.has("vivante"),
          [...ids].filter((x) => x.startsWith("egress") || x === "vivante").join(","));
  // Atteindre un élément par `parentElement.querySelector` cassait tout le branchement dans ce
  // harnais (son DOM est construit à partir des `id`) tout en fonctionnant dans un vrai
  // navigateur : le pire type de défaut d'interface, vert ailleurs et mort ici. Le cas existe
  // pour que la forme ne revienne pas.
  // Les deux cas qui suivent jugent le CODE, pas le fichier : les commentaires sont retirés,
  // sinon une explication qui NOMME la forme interdite ferait rougir le test qui l'interdit
  // (mesuré à la première exécution de ces six cas).
  const CODE = SOURCE.replace(/^\s*\/\/.*$/gm, "");
  vérifie("le script ne cherche pas un élément par son parent (harnais sans querySelector)",
          !/parentElement\.querySelector/.test(CODE),
          "les éléments de cette page sont atteints par id, y compris les libellés");
  vérifie("l'envoi ne fabricote pas de refus : `egress` part seulement si la case est cochée",
          /corps\.egress = true/.test(CODE) && !/corps\.egress = false/.test(CODE),
          "`false` serait une décision explicite de fermer, que l'opérateur n'a pas prise");

  const docV = documentPour(HTML);
  let app = null;
  try {
    app = new Function("document", "window", "fetch", "setTimeout", "console",
                       SOURCE + "\n;return {blocVivant};")(
      docV, {document: docV}, async () => ({ok: false, status: 0, objet: {}}), () => 0,
      {log() {}, warn() {}, error() {}});
  } catch (e) {
    vérifie("le script s'évalue avec les nouveaux éléments", false, String(e));
  }
  if (app) {
    const viv = docV.getElementById("vivante");
    app.blocVivant({mission: "m-test", en_cours: "radon_cc",
                    resume: {selectionne: 2, execute: 1},
                    outils: [{provider: "radon_cc", statut: "selectionne",
                              raison: "exécution en cours", en_cours: true},
                             {provider: "bandit", statut: "execute",
                              raison: "sortie conservée", en_cours: false}]});
    const txt = viv.textContent;
    vérifie("ledger vivant : les outils consignés apparaissent",
            /radon_cc/.test(txt) && /bandit/.test(txt), txt.slice(0, 90));
    vérifie("ledger vivant : « en cours » se lit avec le vocabulaire des six étapes",
            /exécution en cours/.test(txt) && /selectionne/.test(txt), txt.slice(0, 90));
    vérifie("ledger vivant : le nom de la mission et les comptes sont affichés",
            /m-test/.test(txt) && /selectionne 2/.test(txt), txt.slice(0, 120));
    app.blocVivant(null);
    vérifie("ledger vivant : rien à lire ⇒ le bloc se masque, il ne s'affiche pas vide",
            /cache/.test(viv.className) && viv.textContent === "", viv.className);
    app.blocVivant({mission: "m-x", outils: null});
    vérifie("ledger vivant : une réponse sans `outils` ne fait pas tomber la page",
            /cache/.test(viv.className), viv.className);
  }
}

console.log("");
for (const [nom, ok, détail] of MARQUEURS) {
  if (!ok) échecs++;
  console.log((ok ? "OK    " : "ÉCHEC ") + nom + (détail && !ok ? " — " + détail : ""));
}
console.log(`\n${MARQUEURS.length - échecs}/${MARQUEURS.length} vérifications passées`);
process.exit(échecs ? 1 : 0);
