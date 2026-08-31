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

/** Une valeur inconnue rendue LISIBLE : les archives portent des champs polymorphes
 *  (un nom, ou un objet {id, priorite}), et `String(objet)` produit « [object Object] »
 *  — un texte qui n'informe personne. Champs connus nommés, repli JSON explicite. */
function texteSure(v) {
  if (v === null || v === undefined) return "?";
  if (typeof v !== "object") return String(v);
  if (Array.isArray(v)) return v.map(texteSure).join(", ");
  const parties = [];
  if (existe(v.id)) parties.push(String(v.id));
  if (existe(v.nom)) parties.push(String(v.nom));
  if (existe(v.priorite)) parties.push("priorité " + v.priorite);
  return parties.length ? parties.join(" · ") : JSON.stringify(v);
}

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
  // Sur un run REFUSÉ ou en ERREUR, le résumé du moteur porte `findings: 0` alors que
  // RIEN n'a été scanné : un « 0 » affiché en grand chiffre se lit comme une preuve
  // d'absence. Mesuré en E2E réel le 31/08/2026 (refus « aucun outil disponible »
  // affichant « 0 constats »). L'état s'écrit désormais en mots : non produits.
  const arret = /refus|erreur/i.test(String(run.statut || ""));
  const gros = [["constats", run.findings], ["clusters inter-outils", run.clusters_inter_outils],
                ["durée (s)", run.duree_s]];
  gros.forEach(([l, v]) => {
    const d = el("div");
    const nonProduit = arret && l !== "durée (s)" && existe(v);
    d.append(el("b", nonProduit ? "sans" : null, nonProduit ? "non produits" : (existe(v) ? v : "?")),
             el("span", null, l));
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
      // `choisis`/`ecartes` portent tantôt des noms, tantôt des OBJETS (id, priorité) —
      // mesuré sur le bundle réel mux : « {id: grype, priorite: 110} » s'affichait
      // « [object Object] ». Un objet stringifié par le navigateur n'est pas une donnée
      // lisible : chaque champ présent est nommé, et l'objet entier reste le repli.
      ((ssel && ssel.choisis) || []).forEach((x) => ch.append(el("div", "oui", texteSure(x))));
      ((ssel && ssel.ecartes) || []).forEach((x) => ec.append(el("div", "nan", texteSure(x))));
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
function blocFindings(pere, d, index = 4) {
  const findings = Array.isArray(d.findings) ? d.findings : null;
  const s = section(pere, "Constats", index,
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
function blocClusters(pere, cl, index = 5) {
  const st = cl.stats || {};
  const s = section(pere, "Regroupement", index, existe(st.reduction) ? "réduction " + st.reduction : "");
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
function blocRapport(pere, texte, run, index = 6) {
  const s = section(pere, "Rapport humain", index, "texte brut, jamais rendu comme du HTML");
  if (!existe(texte)) { s.append(el("p", "note", "aucun RAPPORT.md (exécution interrompue avant le rendu)")); return s; }
  s.append(el("pre", "rapport", texte));
  const a = el("div", "actions");
  const b = el("button", null, "copier");
  b.onclick = async () => { try { await navigator.clipboard.writeText(texte); b.textContent = "copié"; } catch { b.textContent = "copie refusée par le navigateur"; } };
  a.append(b);
  if (existe(run.sortie)) {
    // Avant : un bouton « archive · … » qui ne faisait RIEN au clic. Un contrôle sans
    // effet est le mensonge le plus discret qu'une interface puisse produire : il
    // copie maintenant le chemin, et dit ce qu'il a fait.
    const b2 = el("button", null, "copier le chemin d'archive");
    b2.onclick = async () => { try { await navigator.clipboard.writeText(run.sortie); b2.textContent = "chemin copié"; } catch { b2.textContent = "copie refusée par le navigateur"; } };
    a.append(b2);
  }
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

/* ------------------------------------------------------------- 7 · historique récent */
/* Le front n'avait AUCUNE vue d'historique alors que l'API sert déjà deux routes
 * (`GET /api/missions`, `GET /api/missions/<id>`, déléguées à `mission_history.py`) :
 * l'opérateur pouvait lancer et suivre une mission, puis perdait toute trace au
 * rechargement de la page. C'était le maillon manquant du parcours « revoir
 * l'historique récent ». Les données ci-dessous viennent de la PROJECTION du lecteur
 * canonique (agnt.history.v1) : statut dérivé du journal, jamais saisi ; counts de
 * findings seulement après lecture d'un artefact (`findings_summary` absent = non
 * produit, PAS zéro) ; chemins absolus et secrets déjà redactés côté serveur. */

const HISTO_LIMITE = 12;
const STATUT_HISTO = {termine: ["ok", "terminé"], refuse: ["attention", "refusé"],
                      erreur: ["erreur", "erreur"], en_file: ["attention", "en file"],
                      en_cours: ["attention", "en cours"], inconnu: ["", "inconnu"]};

function libelleStatut(s) {
  const v = STATUT_HISTO[s];
  return v ? v[1] : (existe(s) ? String(s) : "?");
}

function dateCourte(iso) {
  if (!existe(iso)) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);   // horodatage illisible : brut, pas inventé
  const p = (n) => String(n).padStart(2, "0");
  return p(d.getDate()) + "/" + p(d.getMonth() + 1) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}

function dureeCourte(ms) {
  if (ms === null || ms === undefined || !Number.isFinite(Number(ms))) return "";
  const s = Math.max(0, Math.round(Number(ms) / 1000));
  return s >= 60 ? Math.floor(s / 60) + " min " + (s % 60) + " s" : s + " s";
}

/* La projection serveur échappe `<` et `>` en `&lt;`/`&gt;` parce qu'un client HTML
 * pourrait rendre le texte comme du markup. Cette page ne rend JAMAIS de markup :
 * `textContent` seul, règle non négociable du fichier. Défaire cet échappement avant
 * affichage restitue donc le texte vrai (un extrait de code « if (a < b) » se relit
 * tel quel) sans rouvrir aucune porte : aucun chemin de cette page ne traverse du
 * HTML. Seuls `&lt;` et `&gt;` sont touchés — `&amp;` ne l'est pas, la projection ne
 * l'écrit pas. */
function lisible(t) {
  return typeof t === "string" ? t.replace(/&lt;/g, "<").replace(/&gt;/g, ">") : t;
}

function devoiler(o) {
  if (typeof o === "string") return lisible(o);
  if (Array.isArray(o)) return o.map(devoiler);
  if (o && typeof o === "object") {
    const r = {};
    for (const [k, v] of Object.entries(o)) r[k] = devoiler(v);
    return r;
  }
  return o;
}

async function chargerHistorique() {
  const liste = document.getElementById("historique-liste");
  if (!liste) return;
  const r = await json("/api/missions?limit=" + HISTO_LIMITE);
  liste.textContent = "";
  if (!r.ok) {
    liste.append(el("p", "note", "Historique indisponible — le lecteur d'archive ne répond pas ("
      + (r.status || "aucune réponse") + "). Ce n'est pas « aucune mission » : c'est une lecture "
      + "qui n'a pas eu lieu, et elle est dite comme telle."));
    return;
  }
  const items = (r.objet || {}).items;
  if (!Array.isArray(items)) {
    liste.append(el("p", "note", "Historique : réponse inattendue du lecteur d'archive "
      + "(« items » absent). Aucune mission n'est listée sur une preuve pareille."));
    return;
  }
  const note = document.getElementById("historique-note");
  if (note) note.textContent = items.length
    ? items.length + " mission(s) · " + (existe((r.objet.page || {}).next_cursor) ? "les plus récentes" : "toutes")
    : "";
  if (!items.length) {
    liste.append(el("p", "note", "Aucune mission dans l'archive. La première que tu lances "
      + "apparaîtra ici, avec son statut réel."));
    return;
  }
  items.forEach((it) => {
    const l = el("button", "histo-ligne");
    const st = STATUT_HISTO[it && it.status] || ["", existe(it && it.status) ? String(it.status) : "?"];
    const tete = el("span", "histo-etat");
    tete.append(el("span", "pastille " + st[0], st[1]));
    if (it && it.incomplete) tete.append(el("span", "pastille attention", "incomplète"));
    tete.append(el("span", "histo-date", dateCourte(it && it.created_at)));
    l.append(tete);
    l.append(el("span", "histo-question",
                ((it && it.request && it.request.title) || "question non consignée")));
    const cib = (it && it.target) || {};
    l.append(el("span", "histo-cible", (cib.display_name || "cible ?")
                + (existe(cib.type) ? " · " + cib.type : "")));
    // `findings_summary` n'existe qu'après lecture d'un findings.json PAR LE LECTEUR :
    // absent = constats NON PRODUITS. L'écrire « 0 » serait le faux zéro que toute
    // cette interface refuse d'afficher.
    const fs = it && it.findings_summary;
    l.append(el("span", "histo-constats" + (fs ? "" : " incertain"),
                fs ? fs.total + " constat" + (fs.total > 1 ? "s" : "") : "constats non produits"));
    if (existe(it && it.duration_ms)) l.append(el("span", "histo-duree", dureeCourte(it.duration_ms)));
    l.onclick = () => voirMission(it.mission_id, l);
    liste.append(l);
  });
}

async function voirMission(mid, ligne) {
  if (!existe(mid)) return;
  const liste = document.getElementById("historique-liste");
  if (liste) [].forEach.call(liste.children, (c) => { c.className = String(c.className || "").replace(" choisi", ""); });
  if (ligne) ligne.className += " choisi";
  etatLigne("mission " + mid + " · lecture de l'archive…", "");
  // Le détail s'affiche en haut de page, la ligne cliquée est en bas : sans ce retour
  // visuel, le clic paraissait mort. Gardé derrière une existence — le harnais DOM ne
  // connaît pas scrollIntoView, et une page sans ce bloc reste fonctionnelle.
  const poste = document.getElementById("poste");
  if (poste && typeof poste.scrollIntoView === "function") poste.scrollIntoView({behavior: "smooth"});
  const r = await json("/api/missions/" + encodeURIComponent(mid));
  if (!r.ok) {
    const msg = ((r.objet || {}).error || {}).message || (r.objet || {}).erreur
                || ("lecture impossible (" + (r.status || "aucune réponse") + ")");
    etatLigne("mission " + mid + " · " + msg, "erreur");
    return;
  }
  renduHistorique(r.objet || {});
  etatLigne("mission " + mid + " · relue dans l'archive", "ok");
}

/* L'état d'un outil dans le détail d'historique (contrat `execution-status.v1`) :
 * chaque dimension porte sa PREUVE ; on affiche la valeur, jamais une déduction. */
const EXEC_CLASSE = {termine: "ok", echoue: "erreur", timed_out: "erreur", unavailable: "erreur",
                     cancelled: "attention", en_cours: "attention", non_lance: "attention"};

function celluleDim(valeur, detail) {
  const c = el("span", "pastille " + (EXEC_CLASSE[valeur] || ""), String(valeur || "?"));
  return existe(detail) ? [c, el("span", "raison", " · " + detail)] : [c];
}

function blocExecutionsHisto(pere, executions) {
  const s = section(pere, "Ce qui a tourné", 2,
                    Array.isArray(executions) && executions.length
                      ? executions.length + " outil(s) · dérivé du journal" : "");
  if (!Array.isArray(executions) || !executions.length) {
    s.append(el("p", "note", "Aucune exécution d'outil consignée pour cette mission "
      + "(arrêt avant le plan, ou journal sans événement d'exécution). Aucune conclusion "
      + "ne peut s'appuyer sur un scan qui n'a pas eu lieu."));
    return s;
  }
  const tab = el("table");
  const tete = el("tr");
  ["outil", "exécution", "détection", "complétude et limites"].forEach((x) => tete.append(el("th", null, x)));
  tab.append(tete);
  executions.forEach((x) => {
    const l = el("tr");
    const ex = (x && x.execution) || {};
    const de = (x && x.detection) || {};
    const co = (x && x.completeness) || {};
    const nom = el("td", "outil", (x && (x.display_name || x.provider_id)) || "?");
    const etat = el("td");
    celluleDim(ex.value, ex.reason_code).forEach((n) => etat.append(n));
    const det = el("td");
    if (existe(de.findings_count)) det.append(el("span", null,
      (de.value === "rien_trouve" ? "0 observation sur des cibles analysées"
                                  : de.value + " · " + de.findings_count + " observation(s)")));
    else det.append(el("span", "raison", (de.value || "?")
      + (existe(de.reason_code) ? " · " + de.reason_code : "")));
    const comp = el("td", "raison");
    comp.append(el("span", null, (co.state || "?")
      + ((co.missing || []).length ? " · manquant : " + co.missing.join(", ") : "")
      + ((co.limitations || []).length ? " · limites : " + co.limitations.join(", ") : "")));
    l.append(nom, etat, det, comp);
    tab.append(l);
  });
  s.append(el("p", "note", "Vocabulaire du contrat d'exécution, dérivé du journal de mission : "
    + "« termine » exige une sortie conservée ; « non_lance » dit pourquoi dans le motif ; "
    + "« 0 observation » ne s'écrit que prouvé par des cibles analysées."));
  s.append(tab);
  return s;
}

function blocJournalHisto(pere, evts, index) {
  const s = section(pere, "Journal de mission", index, "messages sûrs, projetés par le lecteur d'archive");
  if (!Array.isArray(evts) || !evts.length) {
    s.append(el("p", "note", "Journal vide ou illisible : la chronologie de cette mission "
      + "n'est pas relisible, et rien n'est reconstitué à sa place."));
    return s;
  }
  const ol = el("ol", "journal");
  evts.forEach((e) => {
    const li = el("li");
    li.append(el("span", "histo-date", dateCourte(e && e.timestamp)),
              el("span", null, lisible((e && e.safe_message) || "événement sans message sûr")));
    ol.append(li);
  });
  s.append(ol);
  s.append(el("p", "note", "Ce journal est la source du statut affiché : un refus s'y lit "
    + "avec sa cause, au moment exact où la mission s'est arrêtée."));
  return s;
}

function renduHistorique(p) {
  const poste = document.getElementById("poste");
  poste.textContent = "";
  const m = p.mission || {};
  const d = p.data || {};
  const rq = d.request || {};

  // barre de retour : l'historique reste visible, la place principale redevient
  // celle d'une nouvelle mission.
  const retour = el("div", "retour");
  const b = el("button", null, "← nouvelle mission");
  b.onclick = () => { vueAccueil(); etatLigne("prêt", "ok"); };
  retour.append(b, el("span", "raison", "mission archivée · relu depuis "
    + (existe(m.mission_id) ? m.mission_id : "?") + " — l'archive est la source, pas la mémoire de la page"));
  poste.append(retour);

  // 1 · bandeau
  const s = section(poste, "Mission archivée", 1,
                    existe(m.mission_id) ? m.mission_id : "");
  const tete = el("div", "entete");
  const ou = el("div", "ou");
  const st = STATUT_HISTO[m.status] || ["", existe(m.status) ? String(m.status) : "?"];
  ou.append(el("span", "pastille " + st[0], st[1]));
  if (existe(m.created_at)) ou.append(el("span", "pastille", "lancée le " + dateCourte(m.created_at)));
  const cib = m.target || {};
  ou.append(el("span", "pastille", "cible · " + (cib.display_name || "?")
               + (existe(cib.type) ? " (" + cib.type + ")" : "")));
  if (existe(m.duration_ms)) ou.append(el("span", "pastille", "durée · " + dureeCourte(m.duration_ms)));
  if (existe(m.run_id)) ou.append(el("span", "pastille", "run_id · " + m.run_id));
  if (m.incomplete) ou.append(el("span", "pastille attention", "INCOMPLÈTE — " + (m.incomplete_reason || "sans événement terminal")));
  const n = el("div", "chiffres");
  const fs = m.findings_summary;
  [["constats", fs ? fs.total : null], ["clusters", existe(m.clusters_count) ? m.clusters_count : null]]
    .forEach(([l, v]) => {
      const dd = el("div");
      dd.append(el("b", null, v === null || v === undefined ? "?" : String(v)), el("span", null, l));
      n.append(dd);
    });
  tete.append(ou, n);
  s.append(tete);
  if (existe(rq.original)) s.append(el("p", "note", "« " + lisible(rq.original) + " »"));
  if (existe(rq.canonical) && rq.canonical !== rq.original)
    s.append(el("p", "note", "forme canonique : " + lisible(rq.canonical)));

  // résultat absent ≠ résultat vide : les deux se lisaient pareil, c'est le défaut
  // que ce bloc a pour raison d'être.
  if (m.status !== "termine") {
    s.append(el("p", "note", "Statut « " + libelleStatut(m.status) + " » : aucun résultat d'analyse "
      + "n'a été produit pour cette mission — rien n'a été scanné, donc aucun comptage de "
      + "constats ne vaut ici. La cause se lit dans le journal, en bas de page."));
  } else if (Array.isArray(p.missing_artifacts) && p.missing_artifacts.length) {
    s.append(el("p", "note", "Artefacts attendus et absents de l'archive : "
      + p.missing_artifacts.join(", ") + ". Les champs correspondants ne sont pas affichés "
      + "plutôt que remplis à zéro : mission close sans ces preuves."));
  } else if (!fs) {
    s.append(el("p", "note", "Constats non produits pour cette mission (aucun findings.json lu) : "
      + "« ? » ci-dessus est un NON LU, pas un zéro."));
  }

  // 2 · ce qui a tourné (contrat d'exécution) — s'attache lui-même à `poste`
  blocExecutionsHisto(poste, d.executions || []);

  // 3 · constats + 4 · regroupement — mêmes formes que findings.json/clusters.json,
  // passées par la projection assainie du lecteur.
  if (Array.isArray(d.findings)) blocFindings(poste, {findings: devoiler(d.findings)}, 3);
  if (existe(d.clusters)) blocClusters(poste, devoiler(d.clusters), 4);

  // 5 · rapport humain
  blocRapport(poste, (d.report || {}).available ? lisible((d.report || {}).content) : undefined, {}, 5);

  // 6 · journal (la cause d'un refus s'y lit)
  blocJournalHisto(poste, d.events || [], 6);

  const pd = document.getElementById("pied");
  pd.textContent = "";
  pd.append(el("div", null, "vue historique · mission " + (m.mission_id || "?")
               + " · statut et comptes dérivés de l'archive par le lecteur canonique, rien par la page"));
}

/* L'écran d'accueil du mode branché : dire le parcours, et surtout ce qu'un refus
 * veut dire — l'opérateur qui voit « refusé » sans explication croit à une panne. */
function vueAccueil() {
  const poste = document.getElementById("poste");
  if (!poste) return;
  poste.textContent = "";
  const s = section(poste, "Nouvelle mission", 1, "trois gestes, rien de plus");
  const etapes = el("div", "etapes");
  [["1", "choisis la cible"], ["2", "écris la mission"], ["3", "RUN"]].forEach(([n, t]) => {
    const d = el("div", "etape");
    d.append(el("b", null, n), el("span", null, t));
    etapes.append(d);
  });
  s.append(etapes);
  s.append(el("p", "note", "Le suivi se lit dans la ligne d'état et le journal vivant, en haut. "
    + "Un refus est un RÉSULTAT : si un binaire manque ou si la politique dit non, la mission "
    + "finit « refusé » avec son motif — jamais un comptage vide."));
  s.append(el("p", "note", "Les missions passées se relisent ci-dessous : statut réel, constats "
    + "prouvés, et le journal qui dit pourquoi celles qui se sont arrêtées se sont arrêtées."));
}


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
  const envoi = await json("/api/runs", {method: "POST", headers: {"Content-Type": "application/json"},
                                         body: JSON.stringify(corps)});
  if (!envoi.ok) {
    etatLigne("refusé avant exécution · " + JSON.stringify(envoi.objet.erreur || envoi.objet), "erreur");
    return;
  }
  const id = envoi.objet.id;
  const pose = Date.now();
  // `position` est la taille de la file à l'insertion (voir api.py) : 1 = ce run est
  // le prochain à partir. L'afficher évite le « pourquoi rien ne bouge » d'un run
  // derrière un autre — la file à un consommateur est un choix, l'écran doit le montrer.
  etatLigne("run " + id + " · en file"
            + (existe(envoi.objet.position) ? " (n°" + envoi.objet.position + " de la file)" : ""),
            "vif");
  let silences = 0;
  for (;;) {
    // Un seul délai, volontairement. L'ancienne expression `id % 2 ? 900 : 1300`
    // évaluait un modulo sur un identifiant de CHAÎNE (NaN, toujours faux) : le
    // ternaire était mort et le délai valait toujours 1300 ms. Relevé longtemps
    // « sans correction » ; corrigé en écrivant ce que le code faisait réellement.
    await new Promise((r) => setTimeout(r, 1100));
    const e = await json("/api/runs/" + id);
    const o = e.objet || {};
    if (e.status === 404) {
      // Le run a été accepté puis a disparu : l'API a redémarré, le registre d'états est en
      // mémoire. Le dire vaut mieux que « ? » pour l'éternité — et renvoyer à la trace disque,
      // qui, elle, a survécu (journal de mission).
      etatLigne("run " + id + " · inconnu du serveur (redémarrage ?) — la trace est restée "
                + "dans le dossier de mission", "erreur");
      chargerHistorique();          // la mission, elle, est sur le disque : elle reste relisible
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
    // Le temps écoulé est mesuré par la page (départ = acceptation du run) : un fait
    // d'horloge côté client, jamais une donnée du moteur — et il ne prétend pas l'être.
    const ecoule = Math.round((Date.now() - pose) / 1000);
    etatLigne("run " + id + " · " + libelleStatut(o.statut)
              + ((o.statut === "en_file" || o.statut === "en_cours") ? " · " + ecoule + " s" : ""),
              (o.statut === "en_file" || o.statut === "en_cours") ? "vif" : (PASTILLE[o.statut] || ""));
    blocVivant(o.vivante);
    if (o.statut === "termine" && o.donnees) {
      blocVivant(null);                     // le ledger complet est dans l'archive, plus rien à suivre
      rendu({...o.donnees, maquette: false});
      chargerHistorique();                  // la mission vient d'entrer dans l'archive : la liste la montre
      return;
    }
    if (o.statut === "refuse" || o.statut === "erreur") {
      // Le refus de politique est un RÉSULTAT, pas une panne : il porte la raison, et
      // n'affiche aucun constat pour ne pas laisser croire que l'analyse a eu lieu.
      const er = o.erreur || {};
      // Deux chemins mènent à « refuse » côté moteur : une EXCEPTION (PolicyError —
      // `er` est rempli) ou un RETOUR code 2 sans exception (politique ou conditions —
      // `er` est ABSENT, mesuré en E2E réel : l'écran affichait « undefined : »).
      // La parole du moteur (resume.motif) est le motif premier ; le détail
      // technique de l'exception complète, il ne remplace pas.
      const motifs = [];
      if (existe((o.resume || {}).motif)) motifs.push(o.resume.motif);
      if (existe(er.lecteur)) motifs.push(er.lecteur);
      if (existe(er.type) || existe(er.message))
        motifs.push((er.type || "erreur") + " : " + (er.message || ""));
      if (!motifs.length) motifs.push("motif non consigné par le moteur");
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
                      autorisation: {allow: false, motifs},
                      // Le ledger du refus, s'il existe : « quel outil était disponible, et
                      // pourquoi il n'a pas tourné ». Absent d'une archive antérieure → le bloc
                      // l'écrira lui-même, on ne fabrique pas une table vide.
                      statuts: ((o.refus || {}).statuts)},
             // `findings`/`clusters` ne sont PLUS forcés à [] : l'ancien forçage
             // affichait « 0 remontés par les outils » sur une mission qui n'en a
             // analysé AUCUN. L'archive décide — absents, le bloc Constats dira
             // « liste non écrite par cette exécution », qui est le fait vrai.
             });
      chargerHistorique();                  // un refus EST un résultat : il entre dans l'archive et l'historique
      return;
    }
  }
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
  document.getElementById("ruban").className = "maquette cache";
  // L'historique et son bouton de rafraîchissement ne vivent QUE branchés : proposer
  // un contrôle d'historique sans lecteur d'archive serait un bouton qui ment.
  const rafraichir = document.getElementById("historique-rafraichir");
  if (rafraichir) {
    rafraichir.disabled = false;
    rafraichir.onclick = () => chargerHistorique();
  }
  chargerHistorique();
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
    if (document.getElementById("cible").children.length) {
      vueAccueil();                        // le parcours se lit dès l'arrivée, pas après un premier RUN
      etatLigne("prêt", "ok");
    }
    return;
  }
  const exemple = await json("donnees_exemple.json");
  if (exemple.ok) rendu(exemple.objet);
  etatLigne("moteur non branché · maquette", "");
  // L'historique suit le moteur : sans API, il ne liste RIEN et le dit — une liste
  // vide sans mot se lirait « aucune mission », qui est un autre mensonge.
  const hl = document.getElementById("historique-liste");
  if (hl) hl.textContent = "historique indisponible — le moteur n'est pas branché "
    + "(api.py non démarré) : aucune mission listée, aucune inventée.";
}
principal();
