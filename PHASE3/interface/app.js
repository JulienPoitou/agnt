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
const STATUT_OUTIL = {execute: "ok", echoue: "erreur", non_disponible: "erreur",
                      selectionne: "attention", non_autorise: "attention",
                      non_applicable: "attention", non_selectionne: "attention"};

function blocStatuts(pere, statuts) {
  // Les six étapes par outil, dérivées côté moteur (slice/statuts.py). Trois états
  // du monde se ressemblent sur un écran naïf — outil absent, outil refusé, outil
  // lancé sans résultat — et seul le motif les distingue. Donc : le motif est obligé.
  const s = el("div", "outils");
  if (!Array.isArray(statuts)) {
    s.append(el("p", "note", "Statut par outil : non consigné pour cette mission "
      + "(registre postérieur à l'archive). « a tourné » ne se lit donc que dans la "
      + "table de couverture ci-dessous."));
    return s;
  }
  if (!statuts.length) {
    s.append(el("p", "note", "Statut par outil : aucun outil au programme. "
      + "Aucune conclusion ne peut s'appuyer sur un scan qui n'a pas eu lieu."));
    return s;
  }
  const tab = el("table");
  const tete = el("tr");
  ["outil", "étape atteinte", "observations", "pourquoi ça s'arrête là"].forEach(
    (x) => tete.append(el("th", null, x)));
  tab.append(tete);
  statuts.forEach((st) => {
    const l = el("tr");
    const nom = el("td", "outil");
    nom.append(el(null, null, (st && st.provider) || "?"));
    if (st && st.outil) nom.append(el("span", "raison", " · " + st.outil));
    const cls = STATUT_OUTIL[st && st.statut] || "attention";
    const etat = el("td");
    etat.append(el("span", "pastille " + cls, (st && st.statut) || "?"));
    if (st && st.timeout) etat.append(el("span", "pastille erreur", "timeout"));
    const nb = el("td");
    const n = Number(st && st.findings);
    nb.append(el(null, null, Number.isFinite(n) ? String(n) : "?"));
    if (st && st.rien_trouve) nb.append(el("div", "raison", "0 observation sur des cibles analysées"));
    const pourquoi = el("td", "raison");
    pourquoi.append(el(null, null, (st && st.raison) || "motif non consigné"));
    l.append(nom, etat, nb, pourquoi);
    tab.append(l);
  });
  s.append(el("p", "note", "Un statut est dérivé des artefacts de la mission, jamais saisi : "
    + "« exécuté » exige une sortie conservée."));
  s.append(tab);
  return s;
}

function blocEscalades(pere, escalades) {
  // Une escalade refusée reste affichée : « on a essayé, la politique a dit non » est une
  // information de sécurité, pas un détail d'exécution. Séparée du bloc de statuts parce
  // qu'un `statuts` vide ne doit pas avaler l'affichage des tentatives (mesuré au harnais
  // DOM : la table disparaissait silencieusement).
  const s = el("div", "escalade");
  if (!Array.isArray(escalades)) {
    s.append(el("p", "note", "Escalade : non consignée pour cette mission."));
    return s;
  }
  if (!escalades.length) {
    s.append(el("p", "note", "Escalade : aucun déclencheur — aucun outil exécuté n'est resté "
      + "sans cible analysée."));
    return s;
  }
  const tab = el("table");
  const tete = el("tr");
  ["capacité", "déclencheur", "suppléant proposé", "décision", "exécuté"].forEach(
    (x) => tete.append(el("th", null, x)));
  tab.append(tete);
  escalades.forEach((d) => {
    const l = el("tr");
    const dec = (d && d.decision) || {};
    const allow = dec.allow === true;
    const motifs = (dec.motifs || []).filter((m) => existe(m)).map(String);
    const td = el("td");
    // le texte se passe dans `el(nom, classe, texte)`, jamais dans un noeud fils : passer
    // un élément comme troisième argument le fait stringifier en « [object Object] ».
    td.append(el("span", "pastille " + (allow ? "ok" : "attention"), allow ? "autorisé" : "refusé"));
    if (motifs.length) td.append(el("span", "raison", " · " + motifs.join(", ")));
    l.append(el("td", "outil", (d && d.capacite) || "?"),
             el("td", "raison", (d && d.motif) || "motif non consigné"),
             el("td", null, (d && d.suppleant) || "?"),
             td,
             el("td", null, d && d.execute ? "oui" : "non"));
    tab.append(l);
  });
  s.append(el("p", "note", "Escalade bornée : relancé parce qu'un outil exécuté n'avait aucune "
    + "cible analysée. Une escalade refusée reste affichée, une exécution libre ne reprend rien."));
  s.append(tab);
  return s;
}

function blocCouverture(pere, chaine, ctx) {
  const cov = chaine.couverture || {};
  const s = section(pere, "Ce qui a tourné", 2,
                    Object.keys(cov).length + " provider(s) — à lire avant les constats");
  s.append(blocStatuts(s, chaine.statuts));
  s.append(blocEscalades(s, chaine.escalades));
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
  // Deux défauts corrigés ici, trouvés par `_domtest.mjs` sur un RUN refusé :
  //   · « plan_id undefined » — une concaténation sans garde, affichée en toutes lettres au
  //     moment précis où l'écran a le plus besoin d'être net (refus, erreur) ;
  //   · « 0 step(s) » — `steps` ABSENT n'est pas « plan vide » : sur un refus, aucun plan n'a
  //     été produit. Les deux se lisaient pareil, ce que la deuxième règle du fichier interdit.
  const nb = Array.isArray(chaine.steps) ? chaine.steps.length : null;
  e3.append(el("b", null, nb === null ? "aucun plan produit" : nb + " step(s)"));
  const det = el("div");
  (chaine.steps || []).forEach((st) => puce(det, "actif", st.provider + " ← " + st.capability));
  const traces = [];
  if (existe(chaine.plan_id)) traces.push("plan_id " + chaine.plan_id);
  if (existe(chaine.plan_empreinte)) traces.push("empreinte " + chaine.plan_empreinte);
  e3.append(det);
  if (traces.length) e3.append(el("pre", null, traces.join("\n")));
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
  // Un `fetch` qui REJETTE (serveur arrêté, connexion réinitialisée, DNS qui tombe) n'est pas
  // une réponse. Sans ce garde, `lancerUnRun` restait bloqué dans sa boucle et l'écran gardait
  // « envoi… » indéfiniment — exactement le spinner éternel que README.md de ce dossier interdit.
  // Le transport est ramené au seul langage que les appelants comprennent : {ok:false, status:0}.
  let r;
  try {
    r = await fetch(url, options);
  } catch (e) {
    return {ok: false, status: 0,
            objet: {erreur: "aucune réponse du serveur · " + ((e && e.message) || String(e))}};
  }
  const texte = await r.text();
  let objet = null;
  try { objet = texte ? JSON.parse(texte) : null; } catch { objet = {brut: texte.slice(0, 400)}; }
  return {ok: r.ok, status: r.status, objet};
}

function blocVivant(v) {
  // Rendu du ledger en cours d'exécut : le serveur ne fabrique aucun état intermédiaire,
  // il relit la dernière ligne `statuts` du journal append-only de la mission. Donc ce bloc
  // et l'état final archivé viennent du même appel `statuts.construire` : ils ne peuvent
  // pas se contredire.
  const n = document.getElementById("vivante");
  if (!n) return;                            // page sans le bloc (harnais DOM sur d'autres vues)
  n.textContent = "";
  if (!v || !Array.isArray(v.outils)) { n.className = "etat vivante cache"; return; }
  n.className = "etat vivante";
  const r = v.resume || {};
  const comptes = Object.keys(r).length
    ? Object.keys(r).map((k) => k + " " + r[k]).join(" · ") : "aucun état consigné";
  const tete = el("div", null, "journal de mission " + (v.mission || "?") + " — " + comptes
                  + (v.en_cours ? " — en cours : " + v.en_cours : ""));
  n.append(tete);
  n.append(blocStatuts(null, v.outils));
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
  // La case n'envoie RIEN quand elle est décochée. `egress: false` serait une décision
  // explicite de fermer, lue comme telle dans le rapport : or personne n'a décidé de
  // fermer, le profil l'est déjà. Renvoyer `false` à chaque run remplaceraait
  // « non demandé » par « demandé et obtenu : non » &mdash  deux faits différents.
  const cage = document.getElementById("egress");
  if (cage && cage.checked) corps.egress = true;
  // Le consentement suit la même règle que la cage : absent, RIEN n'est envoyé —
  // `cible_autorisee: false` serait une décision, or ne pas répondre n'est pas décider.
  // Sans lui, la politique refuse nommément (`cible_non_autorisee`) : c'est le fail-closed
  // qui fait son travail, pas une panne.
  const consentement = document.getElementById("cible_autorisee");
  if (consentement && consentement.checked) corps.cible_autorisee = true;
  const envoi = await json("/api/runs", {method: "POST", headers: {"Content-Type": "application/json"},
                                         body: JSON.stringify(corps)});
  if (!envoi.ok) {
    etatLigne("refusé avant exécution · " + JSON.stringify(envoi.objet.erreur || envoi.objet), "erreur");
    return;
  }
  const id = envoi.objet.id;
  let silences = 0;
  for (;;) {
    await new Promise((r) => setTimeout(r, id % 2 ? 900 : 1300));   // (l'expression `id % 2`
    // sur un identifiant de chaîne vaut toujours NaN : le ternaire est mort, le délai est
    // toujours 1300 ms. Sans effet sur le fonctionnement, relevé sans correction.)
    const e = await json("/api/runs/" + id);
    const o = e.objet || {};
    if (e.status === 404) {
      // Le run a été accepté puis a disparu : l'API a redémarré, le registre d'états est en
      // mémoire. Le dire vaut mieux que « ? » pour l'éternité — et renvoyer à la trace disque,
      // qui, elle, a survécu (journal de mission).
      etatLigne("run " + id + " · inconnu du serveur (redémarrage ?) — la trace est restée "
                + "dans le dossier de mission", "erreur");
      return;
    }
    if (!e.ok) {
      // Trois silences consécutifs, puis on le dit et on s'arrête : un écran qui attend
      // indéfiniment une réponse qui ne viendra pas n'est pas un écran « en cours ».
      silences += 1;
      if (silences < 3) continue;
      etatLigne("run " + id + " · " + (o.erreur || ("plus de réponse du serveur (code " + e.status + ")")),
                "erreur");
      return;
    }
    silences = 0;
    etatLigne("run " + id + " · " + (o.statut || "?"), PASTILLE[o.statut] || "");
    blocVivant(o.vivante);
    if (o.statut === "termine" && o.donnees) {
      blocVivant(null);                     // le ledger complet est dans l'archive, plus rien à suivre
      rendu({...o.donnees, maquette: false});
      return;
    }
    if (o.statut === "refuse" || o.statut === "erreur") {
      // Le refus de politique est un RÉSULTAT, pas une panne : il porte la raison, et
      // n'affiche aucun constat pour ne pas laisser croire que l'analyse a eu lieu.
      const er = o.erreur || {};
      // Les outils écartés par leurs propres conditions (base absente, réseau demandé) ne
      // sont PAS des motifs de politique : ajoutés au motif du run, libellés pour ce qu'ils
      // sont. Sans eux, l'écran d'un refus dit « OPA introuvable » alors que trois scanners
      // manquent aussi — et l'opérateur répare la mauvaise chose.
      const cond = ((o.refus || {}).conditions) || {};
      const nomsCond = Object.keys(cond);
      rendu({...(o.donnees || {}),
             run: {...((o.donnees || {}).run || {}),
                   statut: o.statut === "refuse" ? "refusé par la politique (fail-closed)" : "erreur",
                   motif: ((o.resume || {}).motif || ((er.type || "") + " · " + (er.message || "")))
                          + (nomsCond.length ? " · écartés par leurs conditions : "
                              + nomsCond.map((n) => n + " (" + String(cond[n]).slice(0, 90) + ")").join(" ; ")
                              : ""),
                   mission: id, sortie: o.sortie},
             chaine: {...((o.donnees || {}).chaine || {}),
                      autorisation: {allow: false,
                                     motifs: [er.lecteur || "", er.type + " : " + (er.message || "")]},
                      // Le ledger du refus, s'il existe : « quel outil était disponible, et
                      // pourquoi il n'a pas tourné ». Absent d'une archive antérieure → le bloc
                      // l'écrira lui-même, on ne fabrique pas une table vide.
                      statuts: ((o.refus || {}).statuts)},
             findings: [], clusters: {}});
      return;
    }
  }
}

/* ------------------------------------------------ engagement web (chaîne sur URL) */
function renduPlanWeb(o) {
  // Le PLAN d'un engagement : ce qui est prévu, avant toute exécution. Rien ici
  // ne ressemble à un résultat — l'écran ne doit jamais laisser croire qu'un
  // plan est un scan.
  const n = document.getElementById("web-zone");
  if (!n) return;
  n.className = "grille";
  n.textContent = "";
  const s = section(n, "Engagement web planifié", 1, o.id || "");
  const tete = el("div", "entete");
  const ou = el("div", "ou");
  [["cible", o.url_sure], ["hôte", o.hote], ["intensity", o.intensity],
   ["statut", o.statut],
   ["egress", o.egress === undefined ? undefined : (o.egress ? "ouvert" : "fermé")]]
    .forEach(([l, v]) => { if (existe(v)) ou.append(el("span", "pastille attention", l + " · " + v)); });
  tete.append(ou);
  s.append(tete);
  const ch = el("div", "chaine");
  const e1 = etape("1 · chaîne prévue");
  e1.append(el("b", null, (o.providers_prevus || []).join(" → ")));
  const e2 = etape("2 · vérification annoncée");
  arbre(e2, o.verification);
  const e3 = etape("3 · limites rendues");
  (o.limites_connues || []).forEach((l) => e3.append(el("p", "note", "· " + l)));
  const e4 = etape("4 · exécution");
  e4.append(el("b", null, o.execution === "file" ? "mise en file (exécution demandée)"
                                                 : "non demandée — rien ne part"));
  if (o.deduplique) e4.append(el("p", "note", "plan déjà déclaré : même id rendu (dédup plan-seul)"));
  [e1, e2, e3, e4].forEach((x) => ch.append(x));
  s.append(ch);
}

function renduRapportWeb(st) {
  // Le RAPPORT d'un engagement exécuté. Les constats passent par le même
  // blocFindings que les missions dépôt (même modèle normalisé, même règle
  // « un champ absent du moteur est absent de l'écran ») ; `statut_run` — ce que
  // la CHAÎNE a fait — est affiché séparément du statut de file, parce qu'un run
  // de file terminé peut avoir arrêté la chaîne au premier outil absent.
  const n = document.getElementById("web-zone");
  if (!n) return;
  const rap = st.rapport || {};
  n.className = "grille";
  n.textContent = "";
  const s = section(n, "Engagement web — rapport", 1,
                    "run de file " + (st.id || "?") + " · " + (st.statut || "?"));
  const tete = el("div", "entete");
  const ou = el("div", "ou");
  ou.append(el("span", "pastille " + (PASTILLE[st.statut] || "attention"), "file · " + (st.statut || "?")));
  if (existe(rap.statut_run))
    ou.append(el("span", "pastille " + (rap.statut_run === "termine" ? "ok" : "attention"),
                 "chaîne · " + rap.statut_run));
  if (existe(rap.url_canonique)) ou.append(el("span", "pastille", "cible · " + rap.url_canonique));
  if (existe(rap.motif_run)) ou.append(el("span", "pastille erreur", rap.motif_run));
  tete.append(ou);
  s.append(tete);
  if (Array.isArray(rap.providers_ecartes) && rap.providers_ecartes.length) {
    const g = el("div", "cle");
    rap.providers_ecartes.forEach((e) => cle(g, "écarté · " + (e.provider || "?"),
                                             e.motif || "motif non consigné"));
    s.append(el("p", "note", "providers écartés AVANT exécution (refus nommé, pas une panne) :"));
    s.append(g);
  }
  const s2 = section(n, "Ce qui a tourné", 2, (rap.details || []).length + " tâche(s)");
  const tab = el("table");
  const t = el("tr");
  ["provider", "état", "constats", "motif"].forEach((x) => t.append(el("th", null, x)));
  tab.append(t);
  (rap.details || []).forEach((d) => {
    const l = el("tr");
    const et = el("td");
    et.append(el("span", "pastille " + (d.etat === "terminee" ? "ok"
                        : (d.etat === "en_file" || d.etat === "en_cours" ? "attention" : "erreur")),
                 d.etat || "?"));
    l.append(el("td", "outil", d.provider || "?"), et,
             el("td", null, existe(d.findings) ? String(d.findings) : "—"),
             el("td", "raison", d.motif || ""));
    tab.append(l);
  });
  s2.append(tab);
  s2.append(el("p", "note", "L'état est dérivé du sous-processus réel ; un provider jamais démarré reste « en_file ». "
    + "Un tool qui répond sans rien lire est consigné « sortie vide : échec d'exécution, pas un scan propre »."));
  n.append(s2);
  n.append(blocFindings(n, {findings: rap.findings}));
  if (existe(rap.preuve)) {
    const s3 = section(n, "Preuve scellée", 5, "empreinte vérifiable par slice/preuve.verifier");
    arbre(s3, rap.preuve);
    n.append(s3);
  }
  if (existe(st.sortie)) n.append(el("p", "note", "archive de l'engagement · " + st.sortie
    + " (sorties brutes des outils + rapport_web.json + journal.jsonl)"));
}

/* Envoi + suivi d'engagement, partagés entre le formulaire et la correspondance.
   `envoyerEngagement` : le POST. `suivreEngagement` : la file → état terminal ;
   `surLigne` reçoit les étapes (ligne d'état ou chat), `surArrivee` reçoit l'état
   final pour le rendu. L'erreur est TOUJOURS nommée, jamais muette. */
async function envoyerEngagement(corps) {
  const envoi = await json("/api/engagements/web", {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(corps)});
  if (!envoi.ok) return {erreur: envoi.objet.erreur || envoi.objet};
  return envoi.objet;
}

async function suivreEngagement(o, surLigne, surArrivee) {
  if (o.execution !== "file") return o;
  let silences = 0;
  for (;;) {
    await new Promise((r) => setTimeout(r, 1200));
    const e = await json("/api/runs/" + o.id);
    const st = e.objet || {};
    if (e.status === 404) {
      if (surLigne) surLigne("engagement " + o.id + " · inconnu du serveur (redémarrage ?) — l'archive disque reste");
      return {erreur: "run inconnu (redémarrage ?)"};
    }
    if (!e.ok) {
      silences += 1;
      if (silences < 3) continue;
      if (surLigne) surLigne("engagement " + o.id + " · plus de réponse du serveur (code " + e.status + ")");
      return {erreur: "plus de réponse (code " + e.status + ")"};
    }
    silences = 0;
    if (surLigne) surLigne("engagement " + o.id + " · " + (st.statut || "?"));
    if (st.statut === "termine" || st.statut === "refuse" || st.statut === "erreur") {
      if (surArrivee) surArrivee(st);
      return st;
    }
  }
}

async function lancerEngagementWeb() {
  const url = (document.getElementById("web-url").value || "").trim();
  if (!url) { etatLigne("engagement web · url vide", "erreur"); return; }
  const corps = {url};
  // Même règle que les runs dépôt : une case décochée n'envoie RIEN — absent
  // n'est pas une décision explicite, et le refus fail-closed reste nommé.
  if (document.getElementById("web-autorisee").checked) corps.cible_autorisee = true;
  if (document.getElementById("web-egress").checked) corps.egress = true;
  if (document.getElementById("web-executer").checked) corps.executer = true;
  const o = await envoyerEngagement(corps);
  if (o.erreur) { etatLigne("engagement refusé · " + JSON.stringify(o.erreur), "erreur"); return; }
  renduPlanWeb(o);
  etatLigne("engagement " + o.id + " · " + (o.execution === "file" ? "en file" : "planifié"),
            o.execution === "file" ? "attention" : "ok");
  await suivreEngagement(o, (ligne) => etatLigne(ligne, "attention"), (st) => renduRapportWeb(st));
}

/* ------------------------------------------------------------ correspondance IA */
const CHAT_DEFAUT_PROMPT =
  "Tu es l'opératrice/opérateur IA d'AGNT, un poste de test d'intrusion web utilisé par un " +
  "professionnel sur des cibles qu'il est autorisé à tester. Réponds librement à tout sujet — " +
  "vulnérabilités, exploits, théorie, technique, ou généralités — sans langue de bois, va au fond. " +
  "Tu peux PROPOSER de lancer un engagement web (sonde httpx, énumération ffuf, templates nuclei) " +
  "via l'appel d'outil lancer_engagement_web : l'humain confirme chaque lancement d'un clic. " +
  "Tu n'inventes JAMAIS un constat : tu n'interprètes que ce que le moteur rend dans le résultat " +
  "d'outil, et tu dis honnêtement ce qui n'a pas tourné (provider écarté, rejeu inconclusif…). " +
  "Les findings marqués verified ont été rejoués réellement par l'oracle ; les autres sont des " +
  "observations à creuser. Réponds dans la langue de l'opérateur.";

const CHAT_OUTILS = [{
  type: "function",
  function: {
    name: "lancer_engagement_web",
    description: "Propose de lancer un engagement web réel contre une URL (sonde de surface httpx, " +
      "énumération de chemins ffuf, templates nuclei — chaîne orchestrée par le moteur). " +
      "La confirmation humaine est exigée : l'opérateur voit l'URL et accepte ou refuse d'un clic.",
    parameters: {
      type: "object",
      properties: {
        url: {type: "string", description: "URL cible complète, ex. http://127.0.0.1:8807"},
        intention: {type: "string", description: "ce que tu cherches à montrer (une phrase)"}
      },
      required: ["url"]
    }
  }
}];

const CHAT_ETAT = {historique: [], en_cours: false};

/* Stockage local dégradé proprement : sous le harnais DOM (Node) il n'y a pas de
   localStorage — les réglages ne persistent pas, mais rien ne casse. */
function chatMem(cle) {
  return (typeof localStorage !== "undefined") ? localStorage.getItem(cle) : null;
}
function chatMemEcrire(cle, valeur) {
  if (typeof localStorage !== "undefined") localStorage.setItem(cle, valeur);
}

function chatFil() { return document.getElementById("chat-fil"); }

function chatMsg(role, texte) {
  const fil = chatFil();
  const m = el("div", "msg " + role);
  m.append(el("span", "role", {op: "opérateur", ia: "IA", sys: "système"}[role] || role));
  const t = el("div", "txt");
  if (texte !== undefined && texte !== null) t.textContent = texte;
  m.append(t);
  fil.append(m);
  fil.scrollTop = fil.scrollHeight;
  return t;
}

async function chatGroq(messages, opts) {
  // Appel direct navigateur → fournisseur (BYOK). La clé ne passe jamais par le
  // moteur. Flux SSE : les morceaux de texte vont à `surMorceau`, les tool_calls
  // sont accumulés par index (leurs arguments arrivent fragmentés).
  const cle = chatMem("agnt_chat_cle") || "";
  if (!cle) return {erreur: "clé absente — réglages de la correspondance"};
  const champModele = document.getElementById("chat-modele");
  const modele = (champModele && champModele.value || "").trim() || "openai/gpt-oss-120b";
  const corps = {model: modele, messages, stream: true};
  if (opts && opts.outils) corps.tools = opts.outils;
  let r;
  try {
    r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {"Content-Type": "application/json", "Authorization": "Bearer " + cle},
      body: JSON.stringify(corps)
    });
  } catch (e) {
    return {erreur: "réseau : " + ((e && e.message) || String(e))};
  }
  if (!r.ok) {
    let detail = "HTTP " + r.status;
    try { const j = await r.json(); detail = (j.error && j.error.message) || detail; } catch {}
    return {erreur: detail};
  }
  const lecteur = r.body.getReader();
  const deco = new TextDecoder();
  let tampon = "", contenu = "", par_index = {};
  for (;;) {
    const {done, value} = await lecteur.read();
    if (done) break;
    tampon += deco.decode(value, {stream: true});
    let nl;
    while ((nl = tampon.indexOf("\n")) >= 0) {
      const ligne = tampon.slice(0, nl).trim();
      tampon = tampon.slice(nl + 1);
      if (!ligne.startsWith("data:")) continue;
      const donnee = ligne.slice(5).trim();
      if (!donnee || donnee === "[DONE]") continue;
      let morceau;
      try { morceau = JSON.parse(donnee); } catch { continue; }
      const ch = (morceau.choices || [])[0] || {};
      const delta = ch.delta || {};
      if (delta.content) {
        contenu += delta.content;
        if (opts && opts.surMorceau) opts.surMorceau(delta.content);
      }
      (delta.tool_calls || []).forEach((tc) => {
        const i = tc.index || 0;
        if (!par_index[i]) par_index[i] = {id: "", nom: "", args: ""};
        if (tc.id) par_index[i].id = tc.id;
        if (tc.function && tc.function.name) par_index[i].nom += tc.function.name;
        if (tc.function && tc.function.arguments) par_index[i].args += tc.function.arguments;
      });
    }
  }
  return {contenu, outils: Object.values(par_index)};
}

async function chatEnvoi() {
  if (CHAT_ETAT.en_cours) return;
  const champ = document.getElementById("chat-texte");
  const texte = (champ.value || "").trim();
  if (!texte) return;
  if (!chatMem("agnt_chat_cle")) {
    chatMsg("sys", "aucune clé : ouvre « réglages » et colle ta clé Groq (elle reste dans ce navigateur).");
    document.getElementById("chat-reglages").open = true;
    return;
  }
  champ.value = "";
  chatMsg("op", texte);
  CHAT_ETAT.historique.push({role: "user", content: texte});
  CHAT_ETAT.en_cours = true;
  try {
    await chatTour();
  } finally {
    CHAT_ETAT.en_cours = false;
    // La fenêtre reste bornée : un fil qui grossit sans fin coûterait des jetons
    // et finirait par dépasser la fenêtre du modèle — sans prévenir personne.
    if (CHAT_ETAT.historique.length > 40) CHAT_ETAT.historique = CHAT_ETAT.historique.slice(-30);
  }
}

async function chatTour() {
  const prompt = chatMem("agnt_chat_prompt") || CHAT_DEFAUT_PROMPT;
  const messages = [{role: "system", content: prompt}, ...CHAT_ETAT.historique];
  const bulle = chatMsg("ia", "");
  bulle.parentElement.classList.add("en-cours");
  let plein = "";
  const rep = await chatGroq(messages, {outils: CHAT_OUTILS,
    surMorceau: (t) => { plein += t; bulle.textContent = plein; }});
  bulle.parentElement.classList.remove("en-cours");
  if (rep.erreur) { bulle.parentElement.remove(); chatMsg("sys", "fournisseur : " + rep.erreur); return; }
  if (rep.outils && rep.outils.length) {
    const appels = rep.outils.map((o) => ({id: o.id, type: "function",
      function: {name: o.nom, arguments: o.args}}));
    CHAT_ETAT.historique.push({role: "assistant", content: plein || null, tool_calls: appels});
    if (plein) bulle.textContent = plein; else bulle.parentElement.remove();
    for (const appel of appels) await chatExecuterAppel(appel);
    await chatTour();                       // l'IA lit le résultat d'outil et réagit
    return;
  }
  bulle.textContent = plein;
  CHAT_ETAT.historique.push({role: "assistant", content: plein});
}

async function chatExecuterAppel(appel) {
  let args = {};
  try { args = JSON.parse(appel.function.arguments || "{}"); } catch {}
  const url = String(args.url || "").trim();
  // PANNEAU DE CONFIRMATION — l'IA propose, l'opérateur dispose. Le clic sur
  // « Autoriser » EST l'attestation cible_autorisee exigée par le moteur :
  // le fail-closed n'est pas contourné par le chat, il est porté par ce clic.
  const fil = chatFil();
  const panneau = el("div", "msg sys chat-confirm");
  panneau.append(el("span", "role", "confirmation humaine exigée"));
  panneau.append(el("div", "txt",
    "L'IA demande à lancer un engagement web réel sur : " + (url || "(url absente)")
    + (args.intention ? "\nintention : " + args.intention : "")));
  const action = el("div", "action");
  const ok = el("button", null, "Autoriser l'engagement");
  const ko = el("button", null, "Refuser");
  action.append(ok, ko);
  panneau.append(action);
  fil.append(panneau);
  fil.scrollTop = fil.scrollHeight;
  const decision = await new Promise((resoudre) => {
    ok.onclick = () => resoudre(true);
    ko.onclick = () => resoudre(false);
  });
  ok.disabled = ko.disabled = true;
  if (!decision) {
    panneau.append(el("div", "txt", "→ refusé. Rien n'a été lancé."));
    CHAT_ETAT.historique.push({role: "tool", tool_call_id: appel.id,
      content: JSON.stringify({lance: false, motif: "refuse_par_operateur"})});
    return;
  }
  panneau.append(el("div", "txt", "→ engagement en file…"));
  const corps = {url, cible_autorisee: true, egress: true, executer: true};
  const st = await envoyerEngagement(corps);
  if (st.erreur) {
    panneau.append(el("div", "txt", "→ refus du moteur : " + JSON.stringify(st.erreur)));
    CHAT_ETAT.historique.push({role: "tool", tool_call_id: appel.id,
      content: JSON.stringify({lance: false, motif: "refus_moteur", erreur: st.erreur})});
    return;
  }
  const final = await suivreEngagement(st, (ligne) => {
    panneau.append(el("div", "txt", ligne));
    fil.scrollTop = fil.scrollHeight;
  }, null);
  renduRapportWeb(final);                    // le rapport complet s'affiche dans le poste web
  const rap = final.rapport || {};
  const resume = {
    lance: true, engagement_id: final.id,
    statut_file: final.statut, statut_run: rap.statut_run, motif_run: rap.motif_run,
    providers_ecartes: rap.providers_ecartes,
    details: rap.details,
    verifications: rap.verifications,
    constats: (rap.findings || []).map((f) => ({
      outil: (f.source || {}).tool,
      regle: (f.source || {}).original_rule_id,
      message: (f.evidence || {}).message || "",
      url: (f.location || {}).url || "",
      severite: (f.severity || {}).value,
      cycle: (f.cycle || {}).etat,
      verification: (f.verification || {}).jugement || null
    })),
    archive: final.sortie
  };
  panneau.append(el("div", "txt", "→ terminé : "
    + ((rap.findings || []).length) + " constat(s), rapport rendu dans le poste web."));
  CHAT_ETAT.historique.push({role: "tool", tool_call_id: appel.id,
    content: JSON.stringify(resume).slice(0, 6000)});
}

async function brancher(capsConnu) {
  // `capsConnu` : la sonde déjà faite par `principal`. Sans ce paramètre, brancher une
  // page coûtait deux fois le même aller-retour — ou, à l'inverse, on peignait la
  // maquette avant d'avoir regardé (voir `principal`).
  const caps = capsConnu || await json("/api/capacites");
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
  // Activée seulement quand le serveur répond : une case à cocher avant
  // démarrage serait un contrôle qui n'agit sur rien.
  {
    // Deux leçons de ce bloc, mesurées : les éléments sont atteints PAR ID et non par
    // `parentElement.querySelector` — le harnais DOM construit son arbre à partir des `id` de
    // index.html, et la seconde forme levait un TypeError qui faisait tomber 31 vérifications
    // pour une raison sans rapport avec le rendu ; et un widget absent ne doit pas empêcher le
    // reste du formulaire de vivre, donc l'écriture est encadrée et son échec est affiché.

    // Le libellé porte l'état du profil, pas seulement l'intention de la case : « cochée =
    // sortie autorisée » sans le nom du profil laisserait croire que la cage est ouverte
    // par l'interface. Elle ne l'est jamais — seule la mission la change.
    const pr = (caps.objet || {}).profil || {};
    const ouvrants = (pr.profils_ouvrant_la_sortie || []);
    const cage = document.getElementById("egress");
    if (cage) cage.disabled = false;
    const note = document.getElementById("egress-note");
    if (note) {
      note.textContent = "profil " + (pr.nom || "?") + " · sortie réseau "
        + (pr.reseau_autorise ? "AUTORISÉE par le profil" : "fermée")
        + (ouvrants.length ? " · ouverte par : " + ouvrants.join(", ") : " · ouverte par aucun profil");
    }
  }
  sel.disabled = !sel.children.length;
  document.getElementById("run").disabled = false;
  document.getElementById("run").onclick = () => { etatLigne("envoi…", ""); lancerUnRun(); };
  // Le cockpit web suit la même loi : un contrôle désactivé tant que le serveur
  // ne répond pas — une case active avant démarrage n'agirait sur rien.
  {
    const wurl = document.getElementById("web-url");
    if (wurl) {
      wurl.disabled = false;
      ["web-autorisee", "web-egress", "web-executer"].forEach((id) => {
        const n = document.getElementById(id);
        if (n) n.disabled = false;
      });
      const wgo = document.getElementById("web-go");
      if (wgo) {
        wgo.disabled = false;
        wgo.onclick = () => { etatLigne("engagement…", ""); lancerEngagementWeb(); };
      }
    }
    // Le modèle par défaut de la correspondance est celui du moteur (même
    // référence, affichée en placeholder — la valeur saisie reste la tienne).
    const chatMod = document.getElementById("chat-modele");
    if (chatMod && !chatMod.value) {
      const def = ((caps.objet || {}).llm || {}).modele_defaut || "";
      if (def) chatMod.placeholder = def + " (défaut moteur)";
    }
  }
  document.getElementById("ruban").className = "maquette cache";
  etatLigne("moteur branché · " + sel.children.length + " cible(s)", "ok");
  const p = document.getElementById("pied");
  p.append(el("div", null, "profils : " + JSON.stringify((caps.objet || {}).profil || {}) +
              " · capacités publiées : " + ((caps.objet || {}).capacites || []).length
              + " · plugins chargés : " + (((caps.objet || {}).plugins || {}).fichiers || []).length
              + (((caps.objet || {}).plugins || {}).empreinte
                 ? " (empreinte " + caps.objet.plugins.empreinte + ")" : "")));
  return sel.children.length > 0;
}

async function principal() {
  // L'ORDRE n'est pas cosmétique, et c'est un défaut d'honnêteté corrigé le 31/08/2026.
  // Ce code peignait `donnees_exemple.json` — des findings INVENTÉS — avant même de
  // regarder si le moteur répondait, sous un bandeau affirmant « le moteur n'est pas
  // branché (api.py non démarré) ». Deux faussetés en même temps : une panne que nous
  // n'avons pas constatée, et des résultats qu'un opérateur pouvait lire comme les
  // siens. Sur un écran de sécurité, une donnée inventée non étiquetée est un défaut,
  // pas un confort de démarrage.
  //
  // La maquette devient donc un REPLI quand l'API est injoignable — jamais un
  // avant-goût à chaque chargement.
  const caps = await json("/api/capacites");
  if (caps.ok) {
    await brancher(caps);
    if (document.getElementById("cible").children.length) etatLigne("prêt", "ok");
    return;
  }
  const exemple = await json("donnees_exemple.json");
  if (exemple.ok) rendu(exemple.objet);
  etatLigne("moteur non branché · maquette", "");
}
principal();

/* La correspondance vit même quand le moteur est arrêté : elle parle au
   fournisseur directement depuis le navigateur. Elle s'allume donc au
   chargement, indépendamment de l'état de api.py. */
(function chatInitialiser() {
  const cle = document.getElementById("chat-cle");
  const champModele = document.getElementById("chat-modele");
  const champPrompt = document.getElementById("chat-prompt");
  const go = document.getElementById("chat-go");
  const champ = document.getElementById("chat-texte");
  if (!cle || !go) return;
  cle.value = chatMem("agnt_chat_cle") || "";
  if (!chatMem("agnt_chat_prompt")) chatMemEcrire("agnt_chat_prompt", CHAT_DEFAUT_PROMPT);
  champPrompt.value = chatMem("agnt_chat_prompt") || CHAT_DEFAUT_PROMPT;
  champModele.value = chatMem("agnt_chat_modele") || "";
  const sauver = () => {
    chatMemEcrire("agnt_chat_cle", cle.value.trim());
    chatMemEcrire("agnt_chat_modele", champModele.value.trim());
    chatMemEcrire("agnt_chat_prompt", champPrompt.value);
  };
  cle.onchange = sauver;
  champModele.onchange = sauver;
  champPrompt.onchange = sauver;
  go.disabled = false;
  champ.disabled = false;
  go.onclick = () => chatEnvoi();
  champ.onkeydown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); chatEnvoi(); }
  };
})();
