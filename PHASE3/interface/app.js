/* AGNT — rendu de la maquette.
 *
 * Une seule règle de code : `textContent` partout, jamais `innerHTML`.
 * Le contenu affiché vient de fichiers produits par des outils qui ont lu un dépôt
 * non fiable — le rendre comme du HTML, ce serait laisser ce dépôt écrire dans
 * l'interface (candidat F4 du relevé de crash test). Cette règle est à la fois la
 * sécurité et la sobriété : elle tient sans framework ni dépendance.
 *
 * Les noms de champs lus ici viennent de : analyser.lancer() (resume),
 * analyser._archiver_mission() (run.json), pipeline._rapport(),
 * findings.Finding.to_dict(), clusterer.regrouper(), run.Contexte.to_dict().
 */

const RANG = {CRITICAL: 0, ERROR: 1, HIGH: 2, WARNING: 3, MEDIUM: 4, LOW: 5, INFO: 6, UNKNOWN: 7};
const COULEUR = {
  CRITICAL: "var(--critique)", ERROR: "var(--erreur)", HIGH: "var(--haute)",
  WARNING: "var(--moyenne)", MEDIUM: "var(--moyenne)", LOW: "var(--basse)", UNKNOWN: "#5a6675",
};
const LIBELLE = {
  CRITICAL: "critique", ERROR: "erreur", HIGH: "haute", WARNING: "moyenne",
  MEDIUM: "moyenne", LOW: "basse", UNKNOWN: "non déclarée",
};

function el(nom, classe, texte) {
  const n = document.createElement(nom);
  if (classe) n.className = classe;
  if (texte !== undefined && texte !== null) n.textContent = String(texte);
  return n;
}
function puce(conteneur, classe, texte) { conteneur.append(el("span", "puce " + classe, texte)); }
function cle(pere, libelle, valeur) {
  const d = el("div");
  d.append(el("span", null, libelle), el("b", null, valeur === "" || valeur == null ? "—" : valeur));
  pere.append(d);
}
function section(titre, index, droit) {
  const s = el("section");
  const h = el("h2");
  h.append(el("em", null, String(index).padStart(2, "0")), document.createTextNode(titre));
  if (droit) h.append(el("small", null, droit));
  s.append(h);
  return [s, h];
}

async function donnees() {
  const r = await fetch("donnees_exemple.json");
  return r.json();
}

function blocEntete(pere, run) {
  const [s] = section("Mission", 1, run.mission);
  const tete = el("div", "entete");
  const ou = el("div", "ou");
  const etat = {complet: "ok", arret: "attention", erreur: "erreur"}[run.statut] || "attention";
  ou.append(
    el("span", "pastille " + etat, "statut · " + run.statut),
    el("span", "pastille", "cible · " + run.cible),
    el("span", "pastille", "confiance · " + run.confiance_cible),
    el("span", "pastille", "profil · " + run.profil),
    el("span", "pastille", "moteur d'intention · " + run.moteur),
    el("span", "pastille", "durée · " + run.duree_s + " s")
  );
  const n = el("div", "chiffres");
  [["constats", run.findings], ["clusters inter-outils", run.clusters_inter_outils],
   ["durée (s)", run.duree_s]].forEach(([l, v]) => {
    const d = el("div"); d.append(el("b", null, v), el("span", null, l)); n.append(d);
  });
  tete.append(ou, n);
  s.append(tete, el("p", "note", "« " + run.question + " »"));
  if (run.motif) s.append(el("p", "note", "motif consigné : " + run.motif));
  pere.append(s);
}

function blocCouverture(pere, chaine, ctx) {
  const [s] = section("Ce qui a tourné", 2, "à lire avant les constats");
  const tab = el("table");
  const tete = el("tr");
  ["provider", "a analysé", "n'a pas pu", "limites déclarées par l'adaptateur"].forEach(
    (t) => tete.append(el("th", null, t)));
  tab.append(tete);
  for (const [nom, c] of Object.entries(chaine.couverture || {})) {
    const l = el("tr");
    const a = el("td", "outil");
    a.append(el("span", "oui", "✓ "), el(null, null, nom));
    const ok = el("td");
    (c["analysé"] || []).forEach((f) => ok.append(el("div", null, f)));
    if (!(c["analysé"] || []).length) ok.append(el("span", "raison", "aucun fichier"));
    const nan = el("td");
    (c["non_analysé"] || []).forEach((t) => {
      const d = el("div");
      d.append(el(null, "mort", t.etat), el("span", "raison", " · " + t.cible + " — " + t.raison));
      nan.append(d);
    });
    if (!(c["non_analysé"] || []).length) nan.append(el("span", "raison", "—"));
    const lim = el("td");
    (c.limites || []).forEach((x) => lim.append(el("div", "raison", "· " + x)));
    l.append(a, ok, nan, lim);
    tab.append(l);
  }
  s.append(tab);

  const g = el("div", "cle");
  Object.entries(ctx.outils || {}).forEach(([o, v]) => cle(g, o, v));
  g.append(divRegles(ctx.regles || {}));
  cle(g, "registre (empreinte)", ctx.registre);
  cle(g, "policy.rego (sha256)", ctx.policy);
  cle(g, "base trivy (sha256)", ctx.base_trivy);
  cle(g, "contexte (empreinte)", ctx.contexte_empreinte);
  cle(g, "cible (input_digest)", ctx.input_digest);
  cle(g, "commit scanné", ctx.input_commit + (ctx.working_tree_dirty ? " · arbre MODIFIÉ" : ""));
  s.append(el("p", "note", "Environnement d'exécution — deux rejeux ne sont comparables qu'avec ces valeurs."));
  s.append(g);

  const san = el("div", "cle");
  Object.entries(ctx.sandbox || {}).forEach(([k, v]) =>
    cle(san, k, typeof v === "boolean" ? (v ? "oui" : "non") : v));
  s.append(el("p", "note", "Limites de la cage (déclarées par le profil, pas mesurées ici)."));
  s.append(san);
  pere.append(s);
}

function divRegles(regles) {
  const d = el("div");
  d.append(el("span", null, "jeux de règles montés (sha256)"));
  const b = el("b");
  Object.entries(regles).forEach(([nom, sha]) =>
    b.append(el("div", null, nom + " · " + String(sha).slice(0, 12))));
  d.append(b);
  return d;
}

function blocChaine(pere, chaine) {
  const [s] = section("La chaîne de décision", 3, "ce que le modèle a demandé, ce qui a été autorisé");
  const c = el("div", "chaine");

  const et1 = etape("1 · question");
  et1.append(el("b", null, chaine.requete));

  const et2 = etape("2 · intention");
  const caps = el("div");
  (chaine.capacites_demandees || []).forEach((x) => puce(caps, "actif", "✓ " + x));
  (chaine.capacites_refusees || []).forEach((x) => puce(caps, "refuse", "✗ " + x.id + " — " + x.pourquoi));
  et2.append(el("b", null, (chaine.capacites_demandees || []).length + " capacité(s) retenue(s)"));
  if (chaine.motifs_intent && chaine.motifs_intent.length) {
    et2.append(el("pre", null, "motifs : " + chaine.motifs_intent.join(" · ")));
  }
  et2.prepend(caps);

  const et3 = etape("3 · plan");
  const outils = el("div");
  (chaine.plan_outils || []).forEach((o) => puce(outils, "actif", o));
  et3.append(el("b", null, chaine.plan_id), outils,
             el("pre", null, "empreinte du plan : " + chaine.plan_empreinte));

  const et4 = etape("4 · politique");
  const aut = chaine.autorisation || {};
  const v = el("b", "vraifaux " + (aut.allow ? "" : "non"), aut.allow ? "allow" : "REFUS");
  et4.append(v, el("pre", null, (aut.motifs || []).map((m) => "· " + m).join("\n")));

  const et5 = etape("5 · exécution");
  et5.append(el("b", null, Object.keys(chaine.couverture || {}).length + " provider(s) lancés"),
             el("pre", null, "chaque argv est construit par le cœur depuis le registre : la\n"
                           + "phrase de l'utilisateur et la sortie du modèle n'y ajoutent\n"
                           + "ni drapeau ni chemin (constat A7 de la campagne adverse)."));

  [et1, et2, et3, et4, et5].forEach((e) => c.append(e));
  s.append(c);
  pere.append(s);
}

function etape(titre) {
  const d = el("details");
  const sm = el("summary", null, titre);
  const corps = el("div");
  d.append(sm, corps);
  return corps;
}

function blocFindings(pere, findings) {
  const [s] = section("Constats", 4, findings.length + " sortis des outils, sévérité non réinventée");
  const comptes = {};
  findings.forEach((f) => {
    const sv = (f.severity || {}).value || "UNKNOWN";
    comptes[sv] = (comptes[sv] || 0) + 1;
  });
  const total = findings.length || 1;
  const barre = el("div", "reparties");
  const lgg = el("div", "legende");
  Object.entries(comptes).sort((a, b) => (RANG[a[0]] ?? 9) - (RANG[b[0]] ?? 9)).forEach(([sv, n]) => {
    const i = el("i");
    i.style.background = COULEUR[sv] || COULEUR.UNKNOWN;
    i.style.width = (100 * n / total) + "%";
    barre.append(i);
    const span = el("span");
    span.append(el("i", "couleur"), document.createTextNode(`${LIBELLE[sv] || sv} · ${n}`));
    span.firstChild.style.background = COULEUR[sv] || COULEUR.UNKNOWN;
    lgg.append(span);
  });
  s.append(barre, lgg);

  const liste = el("div", "constats");
  findings.slice().sort((a, b) =>
    ((RANG[(a.severity || {}).value] ?? 9) - (RANG[(b.severity || {}).value] ?? 9))
    || String((a.location || {}).file).localeCompare(String((b.location || {}).file)))
  .forEach((f) => {
    const e = el("div", "constat");
    const tete = el("div", "tete");
    const sv = (f.severity || {}).value || "UNKNOWN";
    const chip = el("span", "sev", LIBELLE[sv] || sv.toLowerCase());
    chip.style.background = (COULEUR[sv] || COULEUR.UNKNOWN) + "22";
    chip.style.color = COULEUR[sv] || COULEUR.UNKNOWN;
    tete.append(chip,
      el("span", "chip", ((f.source || {}).tool) || "?"),
      el("span", "ou", "origine de la sévérité · " + (((f.severity || {}).origine) || "?")),
      el("span", "ou", f.statut || "open"));
    const loc = f.location || {};
    tete.append(el("span", "chip", [loc.asset, loc.file, loc.line].filter(Boolean).join(" · ")));
    e.append(tete);
    const ev = f.evidence || {};
    if (ev.message) e.append(el("p", "msg", ev.message));
    if (ev.titre) e.append(el("p", "msg", ev.titre));
    if (ev.secret) e.append(el("p", "msg", "valeur : " + ev.secret));
    if (ev.cwe && ev.cwe.length) e.append(el("p", "note", "CWE : " + ev.cwe.join(", ")));
    if (ev.extrait) e.append(el("pre", "extrait", ev.extrait));
    const src = f.source || {};
    if (src.original_rule_id) {
      const r = el("p", "note");
      r.append(el("span", "chip", "règle " + src.original_rule_id));
      if (src.canonical_rule_id && src.canonical_rule_id !== src.original_rule_id)
        r.append(document.createTextNode("  →  "), el("span", "chip", "canonique " + src.canonical_rule_id));
      e.append(r);
    }
    liste.append(e);
  });
  s.append(liste);
  pere.append(s);
}

function blocClusters(pere, cl) {
  const st = cl.stats || {};
  const [s] = section("Regroupement", 5, st.reduction ? "réduction " + st.reduction : "");
  const g = el("div", "cle");
  [["findings en entrée", st.findings_en_entree], ["clusters", st.clusters],
   ["regroupés", st.findings_regroupes], ["non regroupés", st.findings_non_regroupes]].forEach(
    ([l, v]) => cle(g, l, v));
  s.append(g);

  const lignes = [["clusters", cl.clusters || []], ["inter-outils", cl.clusters_inter_outils || []]];
  lignes.forEach(([titre, liste]) => {
    if (!liste.length) return;
    s.append(el("p", "note", "· " + titre));
    const tab = el("table");
    const t = el("tr");
    ["id", "clé de regroupement", "confiance", "pourquoi", "membres"].forEach((x) => t.append(el("th", null, x)));
    tab.append(t);
    liste.forEach((k) => {
      const l = el("tr");
      const m = el("td");
      (k.members || []).forEach((id) => m.append(el("span", "chip", id)));
      l.append(el("td", null, k.cluster_id), el("td", null, k.cle),
               el("td", null, k.confiance), el("td", "raison", k.reason), m);
      tab.append(l);
    });
    s.append(tab);
  });
  if ((cl.non_regroupe || []).length) {
    const p = el("p", "note");
    p.append(document.createTextNode("· non regroupés : "));
    (cl.non_regroupe || []).forEach((id) => p.append(el("span", "chip", id)));
    s.append(p);
  }
  pere.append(s);
}

function blocRapport(pere, texte, run) {
  const [s] = section("Rapport humain", 6, "texte brut, jamais rendu comme du HTML");
  const pre = el("pre", "rapport", texte);
  s.append(pre);
  const a = el("div", "actions");
  const b = el("button", null, "copier");
  b.onclick = () => { navigator.clipboard && navigator.clipboard.writeText(texte); b.textContent = "copié"; };
  const b2 = el("button", null, "voir run.json");
  b2.onclick = () => window.open((run.sortie || "") + "/run.json");
  a.append(b, b2);
  s.append(a);
  s.append(el("p", "note", "Ce texte est composé à partir des données des outils. Il est affiché en "
    + "texte échappé parce qu'un dépôt scanné peut y glisser un lien ou un titre de section "
    + "(FAIL C1/C2/C6 du relevé). Le correctif F4 le rendra safe à rendre en markdown."));
  pere.append(s);
}

async function principal() {
  const d = await donnees();
  const poste = document.getElementById("poste");
  blocEntete(poste, d.run);
  blocCouverture(poste, d.chaine, d.contexte);
  blocChaine(poste, d.chaine);
  blocFindings(poste, d.findings || []);
  blocClusters(poste, d.clusters || {});
  blocRapport(poste, d.rapport_markdown || "", d.run || {});
  const p = document.getElementById("pied");
  p.append(el("div", null, "sortie de mission · " + (d.run.sortie || "")));
  p.append(el("div", null, "branchement prévu · POST /api/runs → analyser.lancer(mission, cible, moteur, confiance) "
    + "→ pipeline.executer() → " + (d.maquette ? "MAQUETTE" : "réel")));
  if (!d.maquette) document.getElementById("ruban").classList.add("cache");
}
principal();
