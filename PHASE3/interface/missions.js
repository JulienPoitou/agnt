/* AGNT — missions.js : l'index des missions passées, relu depuis l'archive.
 *
 * Contrat de données : `GET /api/missions` (agnt.history.v1, listing paginé) et
 * `GET /api/missions/<id>` (projection complète). AUCUN contenu n'est inventé ici :
 * ce que le moteur n'a pas consigné s'affiche comme absent, et le module entier se
 * masque si l'API ne répond pas (pas d'index sans archive).
 *
 * Rendu : `textContent` partout, jamais `innerHTML` (même règle qu'app.js). Les
 * constats et le rapport markdown d'une mission terminée sont rendus par les blocs
 * TESTÉS d'app.js (blocFindings, blocRapport) — une seule politique de rendu, sinon
 * elle diverge.
 */
"use strict";

/* ------------------------------------------------------------------ utilitaires repris */
/* `el`, `existe`, `json`, `section`, `blocFindings`, `blocRapport` vivent dans app.js,
   chargé avant ce fichier. On ne les redéfinit pas : un seul endroit pour la vérité. */

const MISSION_ETAT = {en_file: "attention", en_cours: "attention",
                      refuse: "attention", erreur: "erreur", termine: "ok", inconnu: ""};

let missions_page = null;      // curseur de pagination courant (string | null)
let missions_chargees = false; // le module ne sonde l'API qu'une fois

function indexRacine() { return document.getElementById("index-missions"); }

function dateCourte(rfc) {
  // 2026-09-04T17:53:02+00:00 -> 09-04 17:53. Un formatage raté reste affiché brut :
  // réarranger au prix de l'exactitude serait la mauvaise décision.
  if (!existe(rfc)) return "";
  const m = String(rfc).match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  return m ? m[3] + "-" + m[2] + " " + m[4] + ":" + m[5] : String(rfc);
}

function dureeCourte(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return "";
  return n < 1000 ? n + " ms" : (n / 1000).toFixed(n < 10000 ? 1 : 0) + " s";
}

function ligneMission(item) {
  const l = el("div", "mligne");
  const quand = el("span", "mquand", dateCourte(item.created_at));
  const mid = el("span", "mid", existe(item.mission_id) ? String(item.mission_id).slice(-10) : "?");
  const st = el("span", "pastille " + (MISSION_ETAT[item.status] || ""), item.status || "inconnu");
  const cible = el("span", "mcible", existe((item.target || {}).display_name)
                   ? (item.target.type || "?") + " · " + item.target.display_name : "");
  const faits = el("span", "mfaits");
  if (existe(item.findings_summary)) {
    const s = item.findings_summary;
    let txt = "";
    if (typeof s === "object") {
      // {total: N, by_severity: {critique: n, ...}} — chaque niveau compté, rien de plus.
      const morceaux = [];
      if (existe(s.total)) morceaux.push("total " + s.total);
      Object.entries(s.by_severity || {}).forEach(([k, v]) => morceaux.push(k + " " + v));
      txt = morceaux.join(" · ");
    } else {
      txt = String(s);
    }
    faits.append(el("span", "chip", txt || "constats : compte non consigné"));
  } else if (item.artifacts && item.artifacts.findings === false) {
    // findings.json absent : c'est un inconnu (mission non terminée ou archive partielle),
    // pas un « 0 constat ».
    faits.append(el("span", "raison", "constats : non consignés"));
  }
  if (existe(item.duration_ms)) faits.append(el("span", "chip", dureeCourte(item.duration_ms)));
  const voir = el("button", "mvoir", "consulter");
  voir.onclick = () => ouvrirMission(item.mission_id);
  l.append(quand, st, cible, faits, voir);
  return l;
}

async function chargerMissions(plus) {
  const racine = indexRacine();
  if (!racine) return;
  const q = plus && missions_page ? "/api/missions?limit=10&cursor=" + encodeURIComponent(missions_page)
                                  : "/api/missions?limit=10";
  const rep = await json(q);
  if (!rep.ok || !rep.objet || !Array.isArray(rep.objet.items)) {
    // Pas d'archive lisible : le module se masque, il ne simule rien.
    racine.className = "index cache";
    missions_chargees = true;
    return;
  }
  missions_page = (rep.objet.page || {}).next_cursor || null;
  racine.className = "index";
  const corps = racine.querySelector(".mcorps") || racine;
  if (!plus) {
    corps.textContent = "";
    const t = el("div", "mtete");
    t.append(el("span", null, "index des missions — archive append-only"));
    corps.append(t);
  }
  rep.objet.items.forEach((item) => corps.append(ligneMission(item)));
  if (!rep.objet.items.length && !plus) {
    corps.append(el("p", "note", "aucune mission dans l'archive : lance la première depuis le brief."));
  }
  const bouton = corps.querySelector(".mplus");
  if (bouton) bouton.remove();
  if (existe(missions_page)) {
    const b = el("button", "mplus", "charger plus");
    b.onclick = () => chargerMissions(true);
    corps.append(b);
  }
  missions_chargees = true;
}

/* ------------------------------------------------------------------ détail d'une mission */
async function ouvrirMission(mid) {
  const poste = document.getElementById("poste");
  const rep = await json("/api/missions/" + encodeURIComponent(mid));
  if (!rep.ok || !rep.objet) {
    poste.textContent = "";
    const s = el("section");
    s.append(el("p", "note", "mission " + mid + " : projection indisponible (" +
              ((rep.objet || {}).error || {}).code + ")"));
    poste.append(s);
    return;
  }
  const d = rep.objet;
  const m = d.mission || {};
  const data = d.data || {};
  poste.textContent = "";

  // ---- entête : uniquement ce que l'archive a consigné
  const ent = el("section");
  const h = el("h2");
  h.append(el("em", null, "R"), document.createTextNode("Mission " + (existe(m.mission_id) ? m.mission_id : mid)));
  ent.append(h);
  const ou = el("div", "ou");
  ou.append(el("span", "pastille " + (MISSION_ETAT[m.status] || ""), m.status || "inconnu"));
  if (existe((data.request || {}).original)) ou.append(el("span", "note", "« " + data.request.original + " »"));
  if (existe((m.target || {}).display_name)) ou.append(el("span", "pastille", (m.target.type || "?") + " · " + m.target.display_name));
  if (existe(m.run_id)) ou.append(el("span", "pastille", "run " + m.run_id));
  if (existe(m.duration_ms)) ou.append(el("span", "pastille", "durée " + dureeCourte(m.duration_ms)));
  if (existe(m.incomplete)) ou.append(el("span", "pastille erreur", "incomplète · " + (m.incomplete_reason || "")));
  ent.append(ou);
  if (Array.isArray(d.missing_artifacts) && d.missing_artifacts.length) {
    ent.append(el("p", "note", "artefacts absents de l'archive : " + d.missing_artifacts.join(", ")));
  }
  const retour = el("button", "mretour", "← index des missions");
  retour.onclick = () => { poste.textContent = ""; chargerMissions(false); };
  ent.append(retour);
  poste.append(ent);

  // ---- constats : rendus par le bloc TESTÉ d'app.js (mêmes objets, même politique)
  // (ces blocs s'ajoutent eux-mêmes au parent : ne pas append la valeur de retour)
  if (Array.isArray(data.findings)) {
    blocFindings(poste, {findings: data.findings, run: {}});
  }
  // ---- rapport humain, texte échappé, jamais rendu comme du HTML
  if ((data.report || {}).available && existe(data.report.content)) {
    blocRapport(poste, data.report.content, {});
  }

  // ---- journal projeté : la séquence des faits, dans l'ordre d'écriture
  const j = section(poste, "Journal de mission", 9, "events projetés — rien n'est reformulé ici");
  if (Array.isArray(data.events) && data.events.length) {
    const tab = el("table");
    const tete = el("tr");
    ["seq", "fait", "consigné par le moteur"].forEach((x) => tete.append(el("th", null, x)));
    tab.append(tete);
    data.events.forEach((ev) => {
      const l = el("tr");
      l.append(el("td", "raison", String(existe(ev.sequence) ? ev.sequence : "·")),
               el("td", "outil", existe(ev.kind) ? ev.kind : "inconnu"),
               el("td", null, existe(ev.safe_message) ? ev.safe_message : "—"));
      tab.append(l);
    });
    j.append(tab);
  } else {
    j.append(el("p", "note", "journal absent ou illisible pour cette mission."));
  }
  indexRacine().scrollIntoView({behavior: "smooth", block: "start"});
}

/* ------------------------------------------------------------------ branchement */
async function missionsPrincipal() {
  // L'index ne vit que si l'API répond : une archive absente se masque, elle ne se
  // simule pas. Un échec INATTENDU, lui, s'affiche dans le module — un module qui
  // disparaît silencieusement n'est pas un module en panne, c'est un mensonge.
  const racine = indexRacine();
  if (!racine) return;
  try {
    const probe = await json("/api/missions?limit=1");
    if (!probe.ok) {
      // api.py éteint (maquette) OU archive en échec : on le dit, on ne devine pas.
      racine.className = "index";
      racine.append(el("p", "note", "index des missions : archive indisponible (code "
                    + probe.status + ")"));
      return;
    }
    racine.className = "index";
    await chargerMissions(false);
  } catch (e) {
    racine.className = "index";
    racine.append(el("p", "note", "index des missions : erreur inattendue · "
                  + ((e && e.message) || String(e))));
  }
}
missionsPrincipal();
