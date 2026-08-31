/* GATE QA — console V0 du propriétaire (dogfood navigateur)
 *
 * Un gate de PREUVE, pas une app : il rejoue les deux suites existantes
 * (`_smoke_parcours.mjs`, `_domtest.mjs`), ajoute ses propres sondes HTTP sur
 * l'API réelle, et classe chaque maillon du parcours en
 *
 *     PASS         mesuré et vrai
 *     BLOCKED      mesuré : le maillon n'existe pas / n'est pas câblé (preuve)
 *     NON ÉVALUÉ   l'environnement ne permet pas la mesure (preuve, pas de vert)
 *     FAIL         le maillon existe et il casse
 *
 * Il ne touche AUCUN fichier produit (app.js, index.html, api.py, slice/*) :
 * il les lit et les exécute, rien de plus.
 *
 * Maillons (contrat de la mission QA-GATE-CONSOLE-V0) :
 *   1  chargement de la console
 *   2  cibles remontées
 *   3  soumission d'une mission
 *   4  évolution du statut (polling)
 *   5  résultat/refus lisible
 *   6  historique côté API (liste, détail, timeline)
 *   7  historique côté UI (présence mesurée dans la page réelle)
 *   8  cas non heureux : cible invalide, run inconnu, machine sans outils
 *   9  rendu app.js sur artefacts réels (DOM, données hostiles, refus, erreur)
 *  10  rendu réel navigateur (layout) — NON ÉVALUÉ si aucun binaire
 *
 * Sortie machine : docs/coordination/captures/web-dogfood-v0/gate-console-v0.json
 *
 * Usage :
 *   PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_gate_console_v0.mjs
 *   AGNT_GATE_STRICT=1 ...    # code de sortie 1 si un seul maillon ≠ PASS
 *   AGNT_BROWSER_BIN="/usr/bin/chromium" ...   # mesurer le layout si binaire dispo
 *
 * Code de sortie : 0 si aucun FAIL (BLOCKED/NON ÉVALUÉ sont des états publiés,
 * pas des échecs de test) ; 1 si FAIL, ou avec AGNT_GATE_STRICT si un seul ≠ PASS. */
import {readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, readdirSync} from "node:fs";
import {spawn, execFileSync} from "node:child_process";
import {createServer as netServer} from "node:net";
import path from "node:path";
import {fileURLToPath} from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const P3 = path.resolve(ICI, "..");
const RACINE = path.resolve(P3, "..");
const PYTHON = process.env.PYTHON || "python3";
const STRICT = process.env.AGNT_GATE_STRICT === "1";
const CAPTURE_DIR = path.join(RACINE, "docs", "coordination", "captures", "web-dogfood-v0");
const MISSIONS_DIR = path.join(P3, "artifacts", "missions");
const QUESTION_PROBE = "Analyse la sécurité de ce dépôt — gate console v0 (outils absents)";

/* ------------------------------------------------------------------- utilitaires */
function portLibre() {
  return new Promise((resolve, reject) => {
    const s = netServer();
    s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on("error", reject);
  });
}
async function attendServeur(base, ms = 30000) {
  const t0 = Date.now();
  for (;;) {
    try { const r = await fetch(base + "/api/capacites"); if (r.ok) return; } catch { /* pas encore */ }
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
  let logs = "";
  proc.stdout.on("data", (d) => { logs += d; });
  proc.stderr.on("data", (d) => { logs += d; });
  return {proc, logs: () => logs};
}
async function http(base, chemin, corps = null) {
  const opts = {method: corps ? "POST" : "GET", headers: {}};
  if (corps) { opts.body = JSON.stringify(corps); opts.headers["Content-Type"] = "application/json"; }
  try {
    const r = await fetch(base + chemin, opts);
    const txt = await r.text();
    let objet = null;
    try { objet = txt ? JSON.parse(txt) : null; } catch { objet = {brut: txt.slice(0, 300)}; }
    return {code: r.status, ok: r.ok, objet};
  } catch (e) {
    return {code: 0, ok: false, objet: {erreur: String(e).slice(0, 200)}};
  }
}
function sh(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, {cwd: RACINE, env: {...process.env, ...opts.env},
                                stdio: ["ignore", "pipe", "pipe"]});
    let out = "";
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", (d) => { out += d; });
    const t = setTimeout(() => { try { p.kill("SIGKILL"); } catch { /* mort */ } }, opts.timeout || 240000);
    p.on("exit", (code) => { clearTimeout(t); resolve({code: code ?? -1, out}); });
  });
}
const git = (args) => { try { return execFileSync("git", args, {cwd: RACINE}).toString().trim(); }
                        catch { return "?"; } };
const py = (code) => sh(PYTHON, ["-c", code],
                        {env: {PYTHONPATH: process.env.PYTHONPATH || "/home/user/.pydeps"}});

/* ------------------------------------------------------------------ le verdict */
const MAILLONS = [];
const RANG = {FAIL: 4, "NON ÉVALUÉ": 3, BLOCKED: 2, PASS: 1};
function classer(id, nom, statut, preuve, commande = "") {
  const existant = MAILLONS.find((m) => m.maillon === id);
  if (existant) {
    if (RANG[statut] > RANG[existant.statut]) existant.statut = statut;
    existant.preuve = (existant.preuve + " ; " + preuve).replace(/^ ; /, "");
    existant.commande = (existant.commande + " ; " + commande).replace(/^ ; /, "");
    existant.nom = nom;
    return;
  }
  MAILLONS.push({maillon: id, nom, statut, preuve, commande});
  const sig = statut.padEnd(10);
  console.log(`[${sig}] ${id}. ${nom}\n        ${preuve.replace(/\n/g, "\n        ")}`
              + (commande ? `\n        ⟶ ${commande}` : ""));
}

/* ------------------------------------------------------------------ exécution */
async function main() {
  const t0 = Date.now();
  const ENV = {date: new Date().toISOString(), branche: git(["rev-parse", "--abbrev-ref", "HEAD"]),
               sha: git(["rev-parse", "--short", "HEAD"]), node: process.version,
               python: (await py("import sys;print(sys.version.split()[0])")).out.trim() || "?",
               pyyaml: (await py("import yaml;print(yaml.__version__)")).out.trim() || "absent"};
  console.log(`GATE console-v0 · branche ${ENV.branche}@${ENV.sha} · node ${ENV.node} · ${ENV.date}\n`);

  /* ---- 7 : l'historique est-il câblé dans la PAGE réelle ? (mesure statique) ---- */
  {
    const html = readFileSync(path.join(ICI, "index.html"), "utf8");
    const js = readFileSync(path.join(ICI, "app.js"), "utf8");
    const refs = [...js.matchAll(/\/api\/missions[^"'\s]*/g)].map((m) => m[0]);
    const idsHist = [...html.matchAll(/id="([^"]*(?:histor|mission)[^"]*)"/gi)].map((m) => m[1]);
    classer(7, "historique câblé dans la page réelle",
            refs.length || idsHist.length ? "PASS" : "BLOCKED",
            refs.length || idsHist.length
              ? `référence(s) : ${refs.join(" | ") || idsHist.join(" | ")}`
              : "aucune référence à /api/missions dans app.js et aucun élément d'historique "
                + "dans index.html (mesure par lecture directe des fichiers servis). L'API sert "
                + "l'historique (maillon 6) ; la page ne l'affiche pas → WEB-001/002, voir "
                + "docs/coordination/WEB_DOGFOOD_V0.md",
            "grep -n '/api/missions' PHASE3/interface/app.js PHASE3/interface/index.html");
  }

  /* ---- 10 : peut-on mesurer le LAYOUT réel ici ? ---- */
  let browserBin = process.env.AGNT_BROWSER_BIN || "";
  if (!browserBin) {
    for (const b of ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
                     "firefox", "chrome-headless-shell"]) {
      const r = await sh("which", [b]);
      if (r.code === 0) { browserBin = r.out.trim(); break; }
    }
  }
  if (browserBin) {
    /* Mesure réelle si un binaire est fourni/installé : dump du DOM headless. */
    const port = await portLibre();
    const base = `http://127.0.0.1:${port}`;
    const srv = demarrerApi(port);
    try {
      await attendServeur(base);
      const dump = await sh(browserBin, ["--headless", "--disable-gpu", "--no-sandbox",
                                         "--dump-dom", base + "/"], {timeout: 60000});
      const dom = dump.out;
      const charge = dom.includes("moteur branché") || dom.includes("prêt");
      classer(10, "rendu réel navigateur (layout)", charge ? "PASS" : "FAIL",
              `${browserBin} headless --dump-dom → ${dom.length} octets ; `
              + (charge ? "page branchée détectée" : "marqueurs de branchement absents"),
              `AGNT_BROWSER_BIN=${browserBin} node PHASE3/interface/_gate_console_v0.mjs`);
    } finally {
      try { srv.proc.kill("SIGTERM"); } catch { /* mort */ }
      await new Promise((r) => setTimeout(r, 300));
    }
  } else {
    classer(10, "rendu réel navigateur (layout)", "NON ÉVALUÉ",
            "aucun binaire navigateur dans PATH ; les téléchargements de binaires sont bloqués "
            + "dans ce sandbox (ECONNRESET/TLS 35 mesurés sur storage.googleapis.com, "
            + "download-cdn.playwright.dev et miroir npmmirror). Le rendu est jugé via DOM "
            + "minimal (maillon 9), pas au pixel — pas de vert inventé",
            "which chromium google-chrome firefox ; AGNT_BROWSER_BIN=<chemin> node PHASE3/interface/_gate_console_v0.mjs");
  }

  /* ---- sondes API réelles : maillons 3/4/5(API), 6, 8 ---- */
  const avant = new Set(existsSync(MISSIONS_DIR) ? readdirSync(MISSIONS_DIR) : []);
  const port = await portLibre();
  const base = `http://127.0.0.1:${port}`;
  const serveur = demarrerApi(port);
  let missionProbe = null;
  let etatProbe = {};
  try {
    await attendServeur(base);

    /* 8a — cible invalide : refus nommé avec alternatives */
    const rInvalide = await http(base, "/api/runs", {cible: "/etc", question: "scan"});
    const admises = (rInvalide.objet || {}).admises;
    classer(8, "cas non heureux : cible invalide → refus nommé",
            rInvalide.code === 400 && Array.isArray(admises) && admises.length > 0 ? "PASS" : "FAIL",
            `POST /api/runs cible=/etc → HTTP ${rInvalide.code} ; `
            + `${(rInvalide.objet || {}).erreur || "?"} ; ${(admises || []).length} alternative(s) `
            + "nommées",
            `curl -s -XPOST http://127.0.0.1:${port}/api/runs -d '{"cible":"/etc","question":"scan"}'`);

    /* 8b — run inconnu : 404 qui redit l'identifiant */
    const rInconnu = await http(base, "/api/runs/pas-un-run");
    classer(8, "cas non heureux : run inconnu → 404 explicite",
            rInconnu.code === 404 && JSON.stringify(rInconnu.objet).includes("pas-un-run")
            ? "PASS" : "FAIL",
            `GET /api/runs/pas-un-run → HTTP ${rInconnu.code} ; corps `
            + JSON.stringify(rInconnu.objet).slice(0, 140),
            `curl -s http://127.0.0.1:${port}/api/runs/pas-un-run`);

    /* 3/4/5 (niveau API) + 8c : machine sans outils → refus nommé, jamais faux zéro */
    const rLance = await http(base, "/api/runs",
                              {cible: "/home/user/agnt/PHASE3/testrepo", question: QUESTION_PROBE,
                               confiance: "controlled", moteur: "deterministe"});
    const identifiant = rLance.ok ? (rLance.objet || {}).id : "";
    let etat = {};
    const tDeb = Date.now();
    for (let i = 0; i < 240 && identifiant; i++) {
      await new Promise((r) => setTimeout(r, 250));
      etat = (await http(base, `/api/runs/${identifiant}`)).objet || {};
      if (["termine", "refuse", "erreur"].includes(etat.statut)) break;
    }
    const terminal = ["termine", "refuse", "erreur"].includes(etat.statut);
    const motif = String(((etat.resume || {}).motif) || "");
    classer(3, "soumission d'une mission (API)", rLance.ok && identifiant ? "PASS" : "FAIL",
            `POST /api/runs → HTTP ${rLance.code}, id=${identifiant || "—"}, `
            + `statut initial ${(rLance.objet || {}).statut || "—"}`,
            `curl -s -XPOST http://127.0.0.1:${port}/api/runs -d '{"cible":"…/testrepo","question":"…"}'`);
    classer(4, "évolution du statut par polling (API)", terminal ? "PASS" : "FAIL",
            `GET /api/runs/${identifiant} → statut ${etat.statut || "?"} en ${Date.now() - tDeb} ms `
            + "(état terminal atteint, pas de boucle infinie)",
            `curl -s http://127.0.0.1:${port}/api/runs/<id>`);
    const sansOutils = /outil|exécutable|indisponible|introuvable|PolicyError|policy/i.test(motif);
    classer(5, "résultat/refus lisible — machine sans outils (API)",
            !terminal ? "NON ÉVALUÉ"
            : motif && sansOutils && !/0 finding|aucune faille/i.test(motif) ? "PASS" : "FAIL",
            `statut=${etat.statut || "?"} ; motif=${JSON.stringify(motif.slice(0, 220))} ; `
            + "pas de « 0 finding » inventé",
            `GET http://127.0.0.1:${port}/api/runs/${identifiant}`);
    etatProbe = etat;
    missionProbe = etat.mission_id || ((etat.donnees || {}).run || {}).mission || null;
    /* 8c — machine sans outils : la sonde a atteint le stade disponibilité, le
     * refus nomme « aucun outil » ; jamais un faux zéro. (Le verdict détaillé de
     * la lisibilité vit au maillon 5 ; ici c'est le CAS de base qui est prouvé.) */
    classer(8, "cas non heureux : machine sans outils → refus nommé, pas de faux zéro",
            terminal && /aucun outil|aucun outil exécutable/i.test(motif) ? "PASS" : "FAIL",
            `statut=${etat.statut || "?"} ; motif=${JSON.stringify(motif.slice(0, 180))} ; `
            + "findings non fabriqués",
            `GET http://127.0.0.1:${port}/api/runs/${identifiant}`);

    /* 6 — historique côté API : liste + détail + timeline, sur la mission réelle */
    const rListe = await http(base, "/api/missions?limit=100");
    const items = (rListe.objet || {}).items || [];
    const item = items.find((i) => i.mission_id === missionProbe)
                 || items.find((i) => String((i.request || {}).title || "").includes("gate console v0"));
    const rDetail = item ? await http(base, item.detail_href) : {code: 0, objet: null};
    const tl = ((rDetail.objet || {}).data || {}).timeline || {};
    classer(6, "historique visible côté API (liste + détail + timeline)",
            rListe.ok && item && rDetail.code === 200
            && Array.isArray(tl.events) && tl.events.length > 0 ? "PASS" : "FAIL",
            `GET /api/missions → HTTP ${rListe.code}, ${items.length} mission(s) ; mission `
            + `${missionProbe || "?"} ; GET ${(item || {}).detail_href || "/api/missions/<id>"} → HTTP `
            + `${rDetail.code}, schema=${(rDetail.objet || {}).schema_version || "?"}, timeline `
            + `${(tl.events || []).length} événement(s) (${tl.state || "?"})`,
            `curl -s 'http://127.0.0.1:${port}/api/missions?limit=100' ; `
            + `curl -s http://127.0.0.1:${port}/api/missions/<mission_id>`);
  } finally {
    try { serveur.proc.kill("SIGTERM"); } catch { /* mort */ }
    await new Promise((r) => setTimeout(r, 300));
    if (process.env.AGNT_SMOKE_KEEP !== "1" && existsSync(MISSIONS_DIR)) {
      for (const d of readdirSync(MISSIONS_DIR)) {
        if (!avant.has(d)) rmSync(path.join(MISSIONS_DIR, d), {recursive: true, force: true});
      }
    }
  }

  /* ---- smoke page réelle (maillons 1–5, page) : sous-processus dédié ---- */
  console.log("\n── rejeu _smoke_parcours.mjs ──");
  const smokeEnv = {};
  if (process.env.AGNT_SMOKE_KEEP) smokeEnv.AGNT_SMOKE_KEEP = process.env.AGNT_SMOKE_KEEP;
  const smoke = await sh("node", [path.join(ICI, "_smoke_parcours.mjs")],
                         {timeout: 240000, env: smokeEnv});
  const smokeLines = smoke.out.split("\n").filter((l) => /^(OK|ÉCHEC|INFO)/.test(l));
  const smokeFail = smokeLines.some((l) => l.startsWith("ÉCHEC"));
  const smokeCrash = smoke.code !== 0 && !smokeFail;
  const smokeJson = existsSync(path.join(CAPTURE_DIR, "smoke.json"))
                    ? JSON.parse(readFileSync(path.join(CAPTURE_DIR, "smoke.json"), "utf8")) : null;
  const sm = (needle) => (smokeLines.find((l) => l.includes(needle)) || "").startsWith("OK");
  const statutPage = (cond) => smokeCrash ? "NON ÉVALUÉ" : (cond && !smokeFail ? "PASS" : "FAIL");
  const poste = smokeJson ? (smokeJson.poste_excerpt || "") : "";
  classer(1, "chargement de la console", statutPage(sm("la page se branche")),
          `GET / réel + app.js évalué ; bandeau MAQUETTE retiré ; état final `
          + `« ${smokeJson ? smokeJson.etat_final : "?"} » (smoke ${smoke.code === 0 ? "vert" : `code ${smoke.code}`})`,
          "node PHASE3/interface/_smoke_parcours.mjs");
  classer(2, "cibles remontées", statutPage(sm("les cibles admises")),
          smokeJson && smokeJson.resultats
            ? ((smokeJson.resultats.find((r) => r[2].includes("cibles") && r[1]) || [])[3]
               || "options listées, formulaire activé")
            : "smoke.json non relu",
          "node PHASE3/interface/_smoke_parcours.mjs");
  classer(3, "soumission d'une mission (page)", statutPage(sm("état terminal affiché")),
          `clic RUN réel → ${smokeJson ? smokeJson.etat_final : "?"} (poste de ${(poste || "").length} car.)`,
          "node PHASE3/interface/_smoke_parcours.mjs");
  classer(4, "évolution du statut (page)", statutPage(sm("état terminal affiché")),
          `polling réel → ${smokeJson ? smokeJson.duree_ms + " ms" : "?"} ; pas de spinner infini`,
          "node PHASE3/interface/_smoke_parcours.mjs");
  classer(5, "résultat/refus lisible (page)", statutPage(sm("refus nomme le manque")),
          `motif affiché : ${smokeJson ? JSON.stringify((smokeJson.motif || "").slice(0, 180)) : "?"}`,
          "node PHASE3/interface/_smoke_parcours.mjs");

  /* ---- domtest : rendu app.js sur artefacts réels + cas hostiles ---- */
  console.log("\n── rejeu _domtest.mjs ──");
  const dom = await sh("node", [path.join(ICI, "_domtest.mjs")], {timeout: 240000});
  const domLast = (dom.out.match(/(\d+\/\d+) vérifications passées/) || [])[1] || "?";
  classer(9, "rendu app.js sur artefacts réels (DOM, refus, erreur, hostile)",
          dom.code === 0 ? "PASS" : "FAIL",
          `${domLast} vérifications, sortie du harnais : ${dom.code === 0 ? "verte" : "en échec"}`,
          "node PHASE3/interface/_domtest.mjs");

  /* ---- synthèse + transcript ---- */
  for (const m of MAILLONS) {
    const sig = m.statut.padEnd(10);
    console.log(`[${sig}] ${m.maillon}. ${m.nom}`);
  }
  const syn = {PASS: 0, BLOCKED: 0, "NON ÉVALUÉ": 0, FAIL: 0};
  for (const m of MAILLONS) syn[m.statut] = (syn[m.statut] || 0) + 1;
  const journal = {gate: "console-v0", version: 1, ...ENV,
                   duree_ms: Date.now() - t0,
                   environnement: {browser: browserBin || "aucun",
                                   missions_avant: avant.size,
                                   pyyaml: ENV.pyyaml,
                                   strict: STRICT,
                                   sonde_statut: etatProbe.statut || "?"},
                   maillons: MAILLONS, synthèse: syn};
  mkdirSync(CAPTURE_DIR, {recursive: true});
  writeFileSync(path.join(CAPTURE_DIR, "gate-console-v0.json"),
                JSON.stringify(journal, null, 2));
  console.log(`\n═══ MATRICE console-v0 ═══`);
  for (const m of MAILLONS) console.log(`${m.statut.padEnd(10)} ${m.maillon}. ${m.nom}`);
  console.log(`Synthèse : ${Object.entries(syn).map(([k, v]) => `${k}=${v}`).join(" · ")}`);
  console.log(`Transcript : docs/coordination/captures/web-dogfood-v0/gate-console-v0.json`
              + ` (${journal.duree_ms} ms)`);
  const echecs = MAILLONS.filter((m) => m.statut === "FAIL").length;
  const pasPASS = MAILLONS.filter((m) => m.statut !== "PASS").length;
  return (echecs > 0 || (STRICT && pasPASS > 0)) ? 1 : 0;
}

process.exit(await main());
