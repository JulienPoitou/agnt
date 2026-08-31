/* Smoke du parcours navigateur — QA-DOGFOOD V0
 *
 * Ce que ce script fait, et rien d'autre : il joue le happy path du propriétaire
 * contre le VRAI serveur (`api.py`, point d'entrée de production), avec les VRAIS
 * `index.html` + `app.js`, dans un DOM minimal (même contrat que `_domtest.mjs` :
 * éléments atteints par `id`, `textContent` seul, aucun `querySelector`).
 *
 *   charger l'interface        → GET /, bandeau MAQUETTE retiré dès que l'API répond
 *   voir les cibles            → #cible rempli, formulaire activé
 *   soumettre une mission      → clic RUN → POST /api/runs réel
 *   observer le statut         → polling réel de GET /api/runs/<id> + ledger vivant
 *   lire résultat ou refus     → rendu terminal (motif nommé) dans #poste
 *   revoir l'historique        → GET /api/missions + /api/missions/<id> (API ;
 *                                l'UI ne l'expose PAS encore — constaté et dit)
 *
 * Ce qu'il N'EST PAS : un test de layout. Le DOM est simulé, il n'y a pas de
 * navigateur graphique dans ce sandbox (téléchargement Chromium bloqué) : le
 * « rendu visuel » reste NON ÉVALUÉ et le dit. La preuve couvre le contrat et
 * l'exécution réelle de la page, pas le pixel.
 *
 * Usage :
 *   PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_smoke_parcours.mjs
 *   AGNT_SMOKE_KEEP=1 ...        # garder les dossiers de mission créés
 *
 * Sortie : transcript + lignes OK/ÉCHEC/INFO, code 0/1. Le transcript est écrit
 * dans docs/coordination/captures/web-dogfood-v0/smoke.json (racine du dépôt). */
import {readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, readdirSync} from "node:fs";
import {spawn} from "node:child_process";
import {createServer as netServer} from "node:net";
import path from "node:path";
import {fileURLToPath} from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const P3 = path.resolve(ICI, "..");
const RACINE = path.resolve(P3, "..");
const PYTHON = process.env.PYTHON || "python3";
const QUESTION = "Analyse la sécurité de ce dépôt — smoke QA-DOGFOOD V0";
const MISSIONS_DIR = path.join(P3, "artifacts", "missions");

/* ------------------------------------------------------------------ l'API réelle */
function portLibre() {
  return new Promise((resolve, reject) => {
    const s = netServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
    s.on("error", reject);
  });
}

async function attendServeur(base, ms = 30000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await fetch(base + "/api/capacites");
      if (r.ok) return;
    } catch { /* pas encore */ }
    if (Date.now() - t0 > ms) throw new Error(`API injoignable après ${ms} ms`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

function demarrerApi(port) {
  const env = {...process.env};
  if (!env.PYTHONPATH) env.PYTHONPATH = path.join(P3, "slice");
  const proc = spawn(PYTHON, [path.join(ICI, "api.py"), "--host", "127.0.0.1",
                              "--port", String(port)], {cwd: RACINE, env,
    stdio: ["ignore", "pipe", "pipe"]});
  let sortie = "";
  proc.stdout.on("data", (d) => { sortie += d; });
  proc.stderr.on("data", (d) => { sortie += d; });
  return {proc, logs: () => sortie};
}

/* ------------------------------------------------- DOM minimal (ids de index.html) */
class NoeudTexte {
  constructor(t) { this.tagName = "#text"; this.donnee = String(t); }
  get textContent() { return this.donnee; }
}
class Noeud {
  constructor(nom) {
    this.tagName = String(nom).toUpperCase();
    this.nœuds = [];
    this.className = ""; this.style = {}; this.disabled = false;
    this.value = ""; this.type = ""; this.placeholder = ""; this.checked = false;
    this.onclick = null; this.id = "";
  }
  get children() { return this.nœuds.filter((c) => c.tagName !== "#text"); }
  get textContent() { return this.nœuds.map((c) => c.textContent).join(""); }
  set textContent(v) {
    this.nœuds = [];
    if (v !== "" && v !== undefined && v !== null) this.nœuds.push(new NoeudTexte(v));
  }
  append(...q) {
    for (const n of q) this.nœuds.push(typeof n === "string" ? new NoeudTexte(n) : n);
  }
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

/* ------------------------------------------------------------------ observation */
const RESULTATS = [];
function verifie(nom, cond, detail = "") { RESULTATS.push(["CHECK", !!cond, nom, String(detail || "")]); }
function info(nom, detail = "") { RESULTATS.push(["INFO", true, nom, String(detail || "")]); }

async function attendre(fn, timeoutMs, pasMs = 200) {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return {trouve: true, ms: Date.now() - t0, valeur: v};
    if (Date.now() - t0 > timeoutMs) return {trouve: false, ms: Date.now() - t0, valeur: null};
    await new Promise((r) => setTimeout(r, pasMs));
  }
}

async function main() {
  const HIST = {début: new Date().toISOString(), commande: process.argv.join(" "),
                question: QUESTION, node: process.version};
  /* instantané des missions AVANT le smoke : on ne supprime que ce qu'on a créé */
  const avant = new Set(existsSync(MISSIONS_DIR) ? readdirSync(MISSIONS_DIR) : []);
  const port = await portLibre();
  const serveur = demarrerApi(port);
  const BASE = `http://127.0.0.1:${port}`;
  HIST.port = port;
  try {
    await attendServeur(BASE);
    /* ---- 1 + 2 : charger l'interface et voir les cibles ---- */
    const HTML = readFileSync(path.join(ICI, "index.html"), "utf8");
    const SOURCE = readFileSync(path.join(ICI, "app.js"), "utf8");
    const doc = documentPour(HTML);
    try {
      new Function("document", "window", "fetch", "setTimeout", "console", SOURCE)(
        doc, {document: doc, setTimeout},
        (u, o) => fetch(BASE + u, o), setTimeout,
        {log() {}, warn() {}, error() {}});
    } catch (e) {
      verifie("app.js s'évalue sans exception", false, String(e));
      throw e;
    }
    const branche = await attendre(() => {
      const ruban = doc.getElementById("ruban");
      const etat = doc.getElementById("etat");
      return ruban && /cache/.test(ruban.className) && /prêt|moteur branché/.test(etat.textContent);
    }, 30000, 150);
    const sel = doc.getElementById("cible");
    const formOuvre = !doc.getElementById("question").disabled && !doc.getElementById("run").disabled;
    verifie("la page se branche sur l'API réelle (bandeau MAQUETTE retiré)", branche.trouve,
            `${branche.ms} ms`);
    verifie("les cibles admises sont proposées et le formulaire s'active",
            formOuvre && sel.children.length > 0, `${sel.children.length} cible(s)`);
    info("cibles proposées", sel.children.map((c) => `${c.textContent}→${c.value}`).join(" | "));
    if (!sel.children.length) throw new Error("aucune cible proposée");

    /* ---- 3 : soumettre + 4 : suivre le statut ---- */
    doc.getElementById("question").value = QUESTION;
    sel.value = sel.children[0].value;
    doc.getElementById("run").onclick();
    const poll = await attendre(() => {
      const poste = doc.getElementById("poste").textContent;
      const etat = doc.getElementById("etat").textContent;
      if (poste.includes("refusé par la politique")
          || (poste.includes("Mission") && /refusé|erreur|terminé/.test(poste))) return {poste, etat};
      if (/inconnu du serveur|plus de réponse du serveur|refusé avant exécution/.test(etat)) {
        return {poste, etat, panne: true};
      }
      return null;
    }, 180000, 250);
    verifie("la mission aboutit à un état terminal affiché, pas un spinner éternel",
            poll.trouve, `${poll.ms} ms`);
    const final = poll.valeur || {poste: doc.getElementById("poste").textContent,
                                  etat: doc.getElementById("etat").textContent};
    HIST.etat_final = final.etat;
    HIST.poste_excerpt = final.poste.slice(0, 900);
    HIST.poste_longueur = final.poste.length;
    HIST.vivante = doc.getElementById("vivante") && doc.getElementById("vivante").textContent
                   ? doc.getElementById("vivante").textContent.slice(0, 400) : "";
    HIST.pied = doc.getElementById("pied").textContent.slice(0, 300);
    HIST.duree_ms = poll.ms;
    const refuse = /refusé par la politique/.test(final.poste);
    const termine = /terminé|termine/.test(final.poste);
    HIST.resultat = refuse ? "refuse" : (termine ? "termine" : "inconnu");
    const motif = ((final.poste.match(/motif[^\n]{0,180}/i) || [])[0]
                   || (HIST.etat_final || "").slice(0, 180));
    HIST.motif = motif;
    verifie("le résultat/refus porte une motivation nommant la cause",
            refuse || termine || /\berreur\b/.test(final.poste),
            `écran=${HIST.resultat} motif=${JSON.stringify(motif)}`);
    if (refuse) {
      verifie("le refus nomme le manque réel (exécutables/politique), pas une panne générique",
              /aucun outil|introuvable|indisponible|exécutable|PolicyError|policy/i.test(motif), motif);
    }
    info("texte final de l'écran (début)", JSON.stringify(final.poste.slice(0, 260)));

    /* ---- 6 : revoir l'historique (côté API, le contrat que l'UI doit consommer) ---- */
    const rHist = await fetch(BASE + "/api/missions?limit=100");
    const hist = await rHist.json().catch(() => ({}));
    const items = (hist && hist.items) || [];
    const trouve = items.find((i) => (i.request || {}).title &&
                                    String(i.request.title).includes("smoke QA-DOGFOOD V0"));
    HIST.history = {status: rHist.status, total: items.length,
                    mission: trouve ? {mission_id: trouve.mission_id, status: trouve.status,
                                       detail_href: trouve.detail_href} : null};
    verifie("l'API HISTORY sert la mission du run (liste)", rHist.ok && !!trouve,
            `code=${rHist.status} items=${items.length}`);
    if (trouve) {
      HIST.mission_id = trouve.mission_id;
      const rDet = await fetch(BASE + trouve.detail_href);
      const det = await rDet.json().catch(() => ({}));
      const tl = ((det || {}).data || {}).timeline || {};
      const m = (det || {}).mission || {};
      HIST.detail = {status: rDet.status, mission_status: m.status, schema: det && det.schema_version,
                     events: tl.events ? tl.events.length : null, timeline_state: tl.state,
                     missing: ((det || {}).missing_artifacts || []).length};
      verifie("le détail HISTORY redonne la mission avec une timeline",
              rDet.ok && det && det.schema_version === "agnt.history.v1"
              && Array.isArray(tl.events) && tl.events.length > 0,
              JSON.stringify(HIST.detail));
      verifie("le statut de l'historique est terminal et cohérent avec l'écran",
              (m.status === "refuse" || m.status === "termine" || m.status === "erreur"),
              `mission=${m.status} écran=${HIST.resultat}`);
    }
    /* ---- constat : l'UI ne consomme pas encore /api/missions ---- */
    info("UI historique", (SOURCE + "\n" + HTML).includes("/api/missions")
         ? "app.js/index.html référencent /api/missions"
         : "aucune référence à /api/missions dans app.js/index.html — l'API le sert, la page ne l'affiche pas (WEB-001/002, voir la note de preuve)");
  } finally {
    try { serveur.proc.kill("SIGTERM"); } catch { /* déjà mort */ }
    await new Promise((r) => setTimeout(r, 300));
    HIST.logs_api = serveur.logs().slice(0, 600);
    /* nettoyage : uniquement les dossiers créés pendant ce smoke */
    if (process.env.AGNT_SMOKE_KEEP !== "1" && existsSync(MISSIONS_DIR)) {
      for (const d of readdirSync(MISSIONS_DIR)) {
        if (!avant.has(d)) rmSync(path.join(MISSIONS_DIR, d), {recursive: true, force: true});
      }
    }
  }
  /* transcript + verdict */
  const capture = path.join(RACINE, "docs", "coordination", "captures", "web-dogfood-v0");
  mkdirSync(capture, {recursive: true});
  writeFileSync(path.join(capture, "smoke.json"),
                JSON.stringify({...HIST, resultats: RESULTATS}, null, 2));
  let echecs = 0;
  for (const [type, ok, nom, detail] of RESULTATS) {
    if (!ok) echecs++;
    console.log((type === "INFO" ? "INFO  " : ok ? "OK    " : "ÉCHEC ") + nom
                + (detail && !ok ? " — " + detail : ""));
    if (type === "INFO") console.log("       " + detail.slice(0, 320));
  }
  console.log(`\n${RESULTATS.length - echecs}/${RESULTATS.length} vérifications · ${echecs} échec(s)`);
  console.log("Transcript : docs/coordination/captures/web-dogfood-v0/smoke.json");
  return echecs ? 1 : 0;
}

process.exit(await main());
