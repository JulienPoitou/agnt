/* AGNT — rendu de l'écran de mission.
 *
 * Deux modes, un seul contrat de données :
 *   - réel   : `api.py` démarré → les champs viennent des artefacts de la mission ;
 *   - maquette : `donnees_exemple.json` (mêmes clés, valeurs inventées).
 *
 * Une règle de code, non négociable : `textContent` partout, jamais `innerHTML`.
 * Ce qui s'affiche ici a été produit par des outils ayant lu un dépôt non fiable, et ce
 * dépôt peut glisser un lien ou un titre de section dans un `message` (FAIL C1/C2/C6 du
 * relevé de crash test, correctif F4 en file). Échapper n'est pas une prudence de style :
 * c'est la seule chose qui empêche la cible d'écrire dans l'interface.
 *
 * Deuxième règle : un champ absent du moteur est ABSENT de l'écran. Rien n'est remis à 0,
 * rien n'est déduit « probablement » — un 0 affiché à la place d'un inconnu est un mensonge.
 */

const RANG = {CRITICAL: 0, ERROR: 1, HIGH: 2, WARNING: 3, MEDIUM: 4, LOW: 5, INFO: 6, UNKNOWN: 7};
const COULEUR = {CRITICAL: "var(--critique)", ERROR: "var(--erreur)", HIGH: "var(--haute)",
                 WARNING: "var(--moyenne)", MEDIUM: "var(--moyenne)", LOW: "var(--basse)",
                 UNKNOWN: "#5a6675"};
const LIBELLE = {CRITICAL: "critique", ERROR: "erreur", HIGH: "haute", WARNING: "moyenne",
                 MEDIUM: "moyenne", LOW: "basse", INFO: "info", UNKNOWN: "non déclarée"};
const PASTILLE = {complet: "ok", termine: "ok", en_file: "attention", en_cours: "attention",
                  refuse: "attention", erreur: "erreur"};

function el(nom, classe, texte) {
  const n = document.createElement(nom);
  if (classe) n.className = classe;
  if (texte !== undefined && texte !== null) n.textContent = String(texte);
  return n;
}
const existe = (v) => v !== undefined && v !== null && v !== "" &&
                     !(Array.isArray(v) && !v.length) &&
                     !(typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length);

function puce(conteneur, classe, texte) { if (existe(texte)) conteneur.append(el("span", "puce " + classe, texte)); }

function cle(pere, libelle, valeur) {
  if (!existe(valeur)) return;
  const d = el("div");
  d.append(el("span", null, libelle), el("b", null, valeur));
  pere.append(d);
}

function section(pere, titre, index, droit) {
  const s = el("section");
  const h = el("h2");
  h.append(el("em", null, String(index).padStart(2, "0")), document.createTextNode(titre));
  if (existe(droit)) h.append(el("small", null, droit));
  s.append(h);
  pere.append(s);
  return s;
}

/** Arborescence d'un objet inconnu (dict/list de scalaires) — rendu littéral, sans tri ni
 *  reformulation : ce que le moteur a écrit se lit tel quel. */
function arbre(pere, objet, profondeur = 0) {
  if (!existe(objet)) return;
  if (typeof objet !== "object") { pere.append(el("p", "note", String(objet))); return; }
  if (Array.isArray(objet)) {
    const u = el("ul", "arbreet");
    objet.forEach((v) => { const li = el("li"); arbre(li, v, profondeur + 1); u.append(li); });
    pere.append(u);
    return;
  }
  const g = el("div", "cle");
  for (const [k, v] of Object.entries(objet)) {
    if (!existe(v)) continue;
    const d = el("div");
    d.append(el("span", null, k));
    if (typeof v === "object") { const b = el("b"); arbre(b, v, profondeur + 1); d.append(b); }
    else d.append(el("b", null, String(v)));
    g.append(d);
  }
  pere.append(g);
}

/* ----------------------------------------------------------------- 1 · bandeau de mission */
function blocMission(pere, run) {
  const s = section(pere, "Mission", 1, run.mission || (existe(run.dossier) ? "archive · " + run.dossier : ""));
  const tete = el("div", "entete");
  const ou = el("div", "ou");
  const etat = PASTILLE[run.statut] || "attention";
  const pastilles = [
    ["statut", run.statut], ["cible", run.cible], ["confiance", run.confiance_cible],
    ["profil", run.profil], ["moteur d'intention", run.moteur], ["commit", run.input_commit],
  ];
  pastilles.forEach(([l, v]) => {
    if (!existe(v)) return;
    const p = el("span", "pastille " + (l === "statut" ? etat : ""), l + " · " + v);
    ou.append(p);
  });
  if (run.working_tree_dirty) ou.append(el("span", "pastille erreur", "arbre de travail MODIFIÉ"));
  const n = el("div", "chiffres");
  const gros = [["constats", run.findings], ["clusters inter-outils", run.clusters_inter_outils],
                ["durée (s)", run.duree_s]];
  gros.forEach(([l, v]) => {
    const d = el("div");
    d.append(el("b", null, existe(v) ? v : "?"), el("span", null, l));
    n.append(d);
  });
  tete.append(ou, n);
  s.append(tete);
  if (existe(run.question)) s.append(el("p", "note", "« " + run.question + " »"));
  if (existe(run.motif)) s.append(el("p", "note", "motif consigné par le moteur : " + run.motif));
  return s;
}

/* ------------------------------------------------- 2 · ce qui a tourné (avant les constats) */
function blocCouverture(pere, chaine, ctx) {
  const cov = chaine.couverture || {};
  const s = section(pere, "Ce qui a tourné", 2,
                    Object.keys(cov).length + " provider(s) — à lire avant les constats");
  const tab = el("table");
  const t = el("tr");
  ["provider", "a analysé", "n'a pas pu", "limites déclarées par l'adaptateur"].forEach(
    (x) => t.append(el("th", null, x)));
  tab.append(t);
  for (const [nom, c] of Object.entries(cov)) {
    const l = el("tr");
    const a = el("td", "outil");
    a.append(el("span", "oui", "✓ "), el(null, null, nom));
    const ok = el("td");
    ((c && c["analysé"]) || []).forEach((f) => ok.append(el("div", null, f)));
    if (!((c && c["analysé"]) || []).length) ok.append(el("span", "raison", "aucun fichier"));
    const nan = el("td");
    ((c && c["non_analysé"]) || []).forEach((x) => {
      const d = el("div");
      d.append(el(null, "mort", x.etat), el("span", "raison", " · " + x.cible + " — " + x.raison));
      nan.append(d);
    });
    if (!((c && c["non_analysé"]) || []).length) nan.append(el("span", "raison", "—"));
    const lim = el("td");
    ((c && c.limites) || []).forEach((x) => lim.append(el("div", "raison", "· " + x)));
    if (!((c && c.limites) || []).length) lim.append(el("span", "raison", "aucune limite consignée"));
    l.append(a, ok, nan, lim);
    tab.append(l);
  }
  s.append(tab);

  if (existe(ctx)) {
    const g = el("div", "cle");
    Object.entries(ctx.outils || {}).forEach(([o, v]) => cle(g, o, v));
    if (existe(ctx.regles)) {
      const d = el("div");
      d.append(el("span", null, "jeux de règles montés (sha256)"));
      const b = el("b");
      Object.entries(ctx.regles).forEach(([nom, sha]) =>
        b.append(el("div", null, nom + " · " + String(sha).slice(0, 12))));
      d.append(b);
      g.append(d);
    }
    cle(g, "registre (empreinte)", ctx.registre);
    cle(g, "policy.rego (sha256)", ctx.policy);
    cle(g, "base trivy (sha256)", ctx.base_trivy);
    cle(g, "contexte (empreinte)", ctx.contexte_empreinte);
    cle(g, "cible (input_digest)", ctx.input_digest);
    s.append(el("p", "note", "Environnement d'exécution — deux rejeux ne sont comparables qu'avec ces valeurs."));
    s.append(g);

    if (existe(ctx.sandbox)) {
      const san = el("div", "cle");
      Object.entries(ctx.sandbox).forEach(([k, v]) =>
        cle(san, k, typeof v === "boolean" ? (v ? "oui" : "NON") : v));
      s.append(el("p", "note", "Limites de la cage, déclarées par le profil."));
      s.append(san);
    }
  }
  return s;
}

/* ------------------------------------------------------------- 3 · la chaîne de décision */
function blocChaine(pere, chaine) {
  const s = section(pere, "La chaîne de décision", 3,
                    "ce que le modèle a demandé, ce que le registre a retenu, ce que la politique a autorisé");
  const c = el("div", "chaine");

  const e1 = etape("1 · question");
  e1.append(el("b", null, chaine.requete || "—"));
  if (existe(chaine.requete_canonique) && chaine.requete_canonique !== chaine.requete)
    e1.append(el("pre", null, "forme canonique : " + chaine.requete_canonique));

  const e2 = etape("2 · intention");
  const caps = el("div");
  (chaine.capacites_demandees || []).forEach((x) => puce(caps, "actif", "✓ " + x));
  e2.append(el("b", null, (chaine.capacites_demandees || []).length + " capacité(s) retenue(s)"), caps);
  if (existe(chaine.motifs_intent)) {
    const d = el("details");
    d.append(el("summary", null, "pourquoi ces capacités"), el("div", null));
    const corps = el("div");
    arbre(corps, chaine.motifs_intent);
    d.append(corps);
    e2.append(d);
  }
  if (existe(chaine.moteur_intent)) e2.append(el("p", "note", "moteur : " + chaine.moteur_intent));

  const e3 = etape("3 · plan");
  e3.append(el("b", null, (chaine.steps || []).length + " step(s)"));
  const det = el("div");
  (chaine.steps || []).forEach((st) => puce(det, "actif", st.provider + " ← " + st.capability));
  e3.append(det, el("pre", null, "plan_id " + chaine.plan_id + "\nempreinte " + chaine.plan_empreinte));
  if (existe(chaine.selection)) {
    const d = el("details");
    d.append(el("summary", null, "qui a été choisi, qui a été écarté"));
    const tab = el("table");
    const t = el("tr");
    ["capacité", "choisis", "écartés", "motif de sélection"].forEach((x) => t.append(el("th", null, x)));
    tab.append(t);
    for (const [cap, ssel] of Object.entries(chaine.selection)) {
      const l = el("tr");
      const ch = el("td"), ec = el("td");
      ((ssel && ssel.choisis) || []).forEach((x) => ch.append(el("div", "oui", x)));
      ((ssel && ssel.ecartes) || []).forEach((x) => ec.append(el("div", "nan", x)));
      if (!((ssel && ssel.ecartes) || []).length) ec.append(el("span", "raison", "—"));
      l.append(el("td", null, cap), ch, ec, el("td", "raison", (ssel && ssel.motif) || ""));
      tab.append(l);
    }
    d.append(tab);
    e3.append(d);
  }

  const e4 = etape("4 · politique");
  const aut = chaine.autorisation || {};
  e4.append(el("b", "vraifaux " + (aut.allow ? "" : "non"), aut.allow ? "allow" : "REFUS"));
  if ((aut.motifs || []).length)
    e4.append(el("pre", null, aut.motifs.map((m) => "· " + m).join("\n")));
  else e4.append(el("pre", null, "aucun motif consigné"));

  const e5 = etape("5 · argv réellement construits");
  (chaine.steps || []).forEach((st) => {
    const b = el("b", null, st.provider);
    e5.append(b, el("pre", null, [...(st.commande || []), ...(st.args || [])].join(" ")));
  });
  e5.append(el("p", "note", "argv issu du seul registre : la phrase et la sortie du modèle n'y "
    + "ajoutent ni drapeau ni chemin (mesuré A7). Les jetons {BIN} {REGLES} {DB} {sortie} sont "
    + "résolus par le cœur au lancement."));

  [e1, e2, e3, e4, e5].forEach((x) => c.append(x));
  s.append(c);
  return s;
}

function etape(titre) {
  const d = el("details");
  if (titre.startsWith("3") || titre.startsWith("4")) d.open = true;
  d.append(el("summary", null, titre));
  const corps = el("div");
  d.append(corps);
  return corps;
}

/* --------------------------------------------------------------------------- 4 · constats */
function blocFindings(pere, d) {
  const findings = Array.isArray(d.findings) ? d.findings : null;
  const s = section(pere, "Constats", 4,
                    findings === null ? "liste non écrite par cette exécution"
                                      : findings.length + " remontés par les outils");
  if (findings === null) {
    // `findings.json` est absent de l'archive : c'est un inconnu, pas un zéro. Écrire
    // « 0 constat » ici serait fabriquer l'assurance que le projet existe pour refuser.
    s.append(el("p", "note", "Aucun fichier `findings.json` dans l'archive de cette mission : "
      + "le moteur n'a rien consigné, ce n'est pas la même chose qu'« rien trouvé ». "
      + (existe(d.run?.sortie) ? "Archive : " + d.run.sortie : "")));
    return s;
  }
  if (!findings.length) {
    s.append(el("p", "note", "Aucun constat remonté. Ce n'est pas une preuve d'absence : "
      + "voir « ce qui a tourné », et les limites ci-dessus."));
    return s;
  }
  const comptes = {};
  findings.forEach((f) => {
    const sv = (f.severity || {}).value || "UNKNOWN";
    comptes[sv] = (comptes[sv] || 0) + 1;
  });
  const barre = el("div", "reparties"), lgg = el("div", "legende");
  Object.entries(comptes).sort((a, b) => (RANG[a[0]] ?? 9) - (RANG[b[0]] ?? 9)).forEach(([sv, n]) => {
    const i = el("i");
    i.style.background = COULEUR[sv] || COULEUR.UNKNOWN;
    i.style.width = (100 * n / findings.length) + "%";
    barre.append(i);
    const sp = el("span");
    const co = el("i", "couleur");
    co.style.background = COULEUR[sv] || COULEUR.UNKNOWN;
    sp.append(co, document.createTextNode(`${LIBELLE[sv] || sv.toLowerCase()} · ${n}`));
    lgg.append(sp);
  });
  s.append(barre, lgg);

  const liste = el("div", "constats");
  findings.slice().sort((a, b) =>
    ((RANG[((a.severity || {}).value)] ?? 9) - (RANG[((b.severity || {}).value)] ?? 9))
    || String((a.location || {}).file).localeCompare(String((b.location || {}).file)))
  .forEach((f) => {
    const e = el("div", "constat");
    const tete = el("div", "tete");
    const sv = (f.severity || {}).value || "UNKNOWN";
    const chip = el("span", "sev", LIBELLE[sv] || String(sv).toLowerCase());
    chip.style.background = (COULEUR[sv] || COULEUR.UNKNOWN) + "22";
    chip.style.color = COULEUR[sv] || COULEUR.UNKNOWN;
    tete.append(chip);
    if (existe((f.source || {}).tool)) tete.append(el("span", "chip", f.source.tool));
    if (existe(f.id)) tete.append(el("span", "chip", f.id));
    const loc = f.location || {};
    if (existe(loc.file)) tete.append(el("span", "chip", [loc.asset, loc.file, loc.line].filter(existe).join(" · ")));
    tete.append(el("span", "ou", "sévérité déclarée par · " + (((f.severity || {}).origine) || "?")));
    e.append(tete);
    const ev = f.evidence || {};
    ["message", "titre", "description"].forEach((k) => { if (existe(ev[k])) e.append(el("p", "msg", ev[k])); });
    if (existe(ev.secret)) e.append(el("p", "msg", "valeur : " + ev.secret));
    if (existe(ev.cwe)) e.append(el("p", "note", "CWE : " + (Array.isArray(ev.cwe) ? ev.cwe.join(", ") : ev.cwe)));
    if (existe(ev.extrait)) e.append(el("pre", "extrait", ev.extrait));
    const src = f.source || {};
    if (existe(src.original_rule_id)) {
      const p = el("p", "note");
      p.append(el("span", "chip", "règle " + src.original_rule_id));
      if (existe(src.canonical_rule_id) && src.canonical_rule_id !== src.original_rule_id)
        p.append(document.createTextNode("  →  "), el("span", "chip", "canonique " + src.canonical_rule_id));
      e.append(p);
    }
    if (existe(f.statut)) e.append(el("p", "note", "statut : " + f.statut));
    liste.append(e);
  });
  s.append(liste);
  return s;
}

/* ------------------------------------------------------------------------ 5 · regroupement */
function blocClusters(pere, cl) {
  const st = cl.stats || {};
  const s = section(pere, "Regroupement", 5, existe(st.reduction) ? "réduction " + st.reduction : "");
  const g = el("div", "cle");
  [["findings en entrée", st.findings_en_entree], ["clusters", st.clusters],
   ["regroupés", st.findings_regroupes], ["non regroupés", st.findings_non_regroupes]].forEach(
    ([l, v]) => cle(g, l, v));
  if (g.children.length) s.append(g);
  [["clusters", cl.clusters || []], ["inter-outils", cl.clusters_inter_outils || []]].forEach(([titre, liste]) => {
    if (!liste.length) return;
    s.append(el("p", "note", "· " + titre));
    const tab = el("table");
    const t = el("tr");
    ["id", "clé de regroupement", "confiance", "motifs du regroupement", "membres"].forEach(
      (x) => t.append(el("th", null, x)));
    tab.append(t);
    liste.forEach((k) => {
      const l = el("tr");
      const m = el("td");
      (k.members || []).forEach((id) => m.append(el("span", "chip", id)));
      const r = el("td");
      (Array.isArray(k.reason) ? k.reason : [k.reason]).filter(existe).forEach((x) =>
        r.append(el("div", "raison", x)));
      l.append(el("td", null, k.cluster_id), el("td", null, k.cle), el("td", null, k.confiance), r, m);
      tab.append(l);
    });
    s.append(tab);
  });
  if ((cl.non_regroupe || []).length) {
    const p = el("p", "note");
    p.append(document.createTextNode("· non regroupés : "));
    cl.non_regroupe.forEach((id) => p.append(el("span", "chip", id)));
    s.append(p);
  }
  return s;
}

/* ---------------------------------------------------------------------------- 6 · rapport */
function blocRapport(pere, texte, run) {
  const s = section(pere, "Rapport humain", 6, "texte brut, jamais rendu comme du HTML");
  if (!existe(texte)) { s.append(el("p", "note", "aucun RAPPORT.md (exécution interrompue avant le rendu)")); return s; }
  s.append(el("pre", "rapport", texte));
  const a = el("div", "actions");
  const b = el("button", null, "copier");
  b.onclick = async () => { try { await navigator.clipboard.writeText(texte); b.textContent = "copié"; } catch { b.textContent = "copie refusée par le navigateur"; } };
  a.append(b);
  if (existe(run.sortie)) a.append(el("button", null, "archive · " + run.sortie));
  s.append(a);
  s.append(el("p", "note", "Affiché en texte échappé parce qu'un dépôt scanné peut glisser un lien ou un "
    + "titre de section dans un message d'outil (C1/C2/C6 du relevé). F4 le rendra safe à rendre en markdown."));
  return s;
}

/* ------------------------------------------------------------------------------ rendu */
function rendu(d) {
  const poste = document.getElementById("poste");
  poste.textContent = "";
  // `cible` est portée par le plan (`chaine.cible`), pas par le résumé de mission ;
  // le bandeau fusionne les deux sans inventer de champ.
  blocMission(poste, {cible: (d.chaine || {}).cible, ...(d.run || {})});
  blocCouverture(poste, d.chaine || {}, d.contexte || {});
  blocChaine(poste, d.chaine || {});
  blocFindings(poste, d);
  blocClusters(poste, d.clusters || {});
  blocRapport(poste, d.rapport_markdown, d.run || {});
  const p = document.getElementById("pied");
  p.textContent = "";
  if (existe((d.run || {}).sortie)) p.append(el("div", null, "archive de mission · " + d.run.sortie));
  p.append(el("div", null, "aucune valeur n'est ajoutée, arrondie ou comblée par cette page : "
    + "tout vient des artefacts écrits par le moteur."));
}

/* ------------------------------------------------------------------------ branchement API */
async function json(url, options) {
  const r = await fetch(url, options);
  const texte = await r.text();
  let objet = null;
  try { objet = texte ? JSON.parse(texte) : null; } catch { objet = {brut: texte.slice(0, 400)}; }
  return {ok: r.ok, status: r.status, objet};
}

function etatLigne(texte, classe) {
  const n = document.getElementById("etat");
  n.textContent = texte;
  n.className = "etat " + (classe || "");
}

async function lancerUnRun() {
  const corps = {
    cible: document.getElementById("cible").value,
    question: document.getElementById("question").value.trim(),
    confiance: document.getElementById("confiance").value,
    moteur: document.getElementById("moteur").value,
  };
  const modele = document.getElementById("modele").value.trim();
  if (modele) corps.modele = modele;
  const envoi = await json("/api/runs", {method: "POST", headers: {"Content-Type": "application/json"},
                                         body: JSON.stringify(corps)});
  if (!envoi.ok) {
    etatLigne("refusé avant exécution · " + JSON.stringify(envoi.objet.erreur || envoi.objet), "erreur");
    return;
  }
  const id = envoi.objet.id;
  for (;;) {
    await new Promise((r) => setTimeout(r, id % 2 ? 900 : 1300));
    const e = await json("/api/runs/" + id);
    const o = e.objet || {};
    etatLigne("run " + id + " · " + (o.statut || "?"), PASTILLE[o.statut] || "");
    if (o.statut === "termine" && o.donnees) { rendu({...o.donnees, maquette: false}); return; }
    if (o.statut === "refuse" || o.statut === "erreur") {
      // Le refus de politique est un RÉSULTAT, pas une panne : il porte la raison, et
      // n'affiche aucun constat pour ne pas laisser croire que l'analyse a eu lieu.
      const er = o.erreur || {};
      rendu({...(o.donnees || {}),
             run: {...((o.donnees || {}).run || {}),
                   statut: o.statut === "refuse" ? "refusé par la politique (fail-closed)" : "erreur",
                   motif: (o.resume || {}).motif || ((er.type || "") + " · " + (er.message || "")),
                   mission: id, sortie: o.sortie},
             chaine: {...((o.donnees || {}).chaine || {}),
                      autorisation: {allow: false,
                                     motifs: [er.lecteur || "", er.type + " : " + (er.message || "")]}},
             findings: [], clusters: {}});
      return;
    }
  }
}

async function brancher() {
  const caps = await json("/api/capacites");
  if (!caps.ok) {                                   // pas d'API → on reste en maquette, en le disant
    etatLigne("moteur non branché · maquette", "");
    return false;
  }
  const cibles = await json("/api/cibles");
  const sel = document.getElementById("cible");
  sel.textContent = "";
  ((cibles.objet || {}).cibles || []).forEach((c) => {
    const o = el("option", null, c.nom + (c.langages.length ? " · " + c.langages.join("/") : ""));
    o.value = c.chemin;
    sel.append(o);
  });
  const l = (caps.objet || {}).llm || {};
  const champ = document.getElementById("modele");
  champ.disabled = false;
  champ.placeholder = l.cle_presente ? (l.modele_defaut + " (défaut)") :
    "GROQ_API_KEY absente → moteur déterministe";
  const conf = document.getElementById("confiance");
  conf.textContent = "";
  ((caps.objet || {}).confiances || ["controlled", "untrusted"]).forEach((x) => conf.append(el("option", null, x)));
  document.getElementById("question").disabled = false;
  document.getElementById("moteur").disabled = false;
  sel.disabled = !sel.children.length;
  document.getElementById("run").disabled = false;
  document.getElementById("run").onclick = () => { etatLigne("envoi…", ""); lancerUnRun(); };
  document.getElementById("ruban").className = "maquette cache";
  etatLigne("moteur branché · " + sel.children.length + " cible(s)", "ok");
  const p = document.getElementById("pied");
  p.append(el("div", null, "profils : " + JSON.stringify((caps.objet || {}).profil || {}) +
              " · capacités publiées : " + ((caps.objet || {}).capacites || []).length));
  return sel.children.length > 0;
}

async function principal() {
  const exemple = await json("donnees_exemple.json");
  if (exemple.ok) rendu(exemple.objet);
  const reel = await brancher();
  if (reel && document.getElementById("cible").children.length) etatLigne("prêt", "ok");
}
principal();
