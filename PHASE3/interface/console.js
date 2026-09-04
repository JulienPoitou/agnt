/* AGNT — console.js : habillage, jamais des données.
 *
 * Ce fichier ne lit aucune API et n'affiche aucun contenu du moteur : tout ce qui
 * vient du moteur passe par app.js (textContent, rien d'inventé). Ici, trois
 * cosmétiques qui restent vrais :
 *   1. le choix du tube (phosphore) — une préférence d'affichage, comme un thème ;
 *   2. l'allumage du tube quand un run PART — une transition, pas une télémétrie ;
 *   3. le point « canal » qui pulse quand l'état publié dit en_cours — il lit
 *      l'état que app.js a déjà écrit, il n'en fabrique pas.
 * Tout est défensif : sans canvas, sans localStorage, sans MutationObserver, la
 * page reste pleinement fonctionnelle.
 */
(function () {
  "use strict";

  /* 1 · le tube */
  var TUBES = ["ambre", "verde", "blanc"];
  function poser(t) {
    if (TUBES.indexOf(t) < 0) t = "ambre";
    document.body.className = "t-" + t;
    var boutons = document.querySelectorAll("#tubes button");
    for (var i = 0; i < boutons.length; i++) {
      boutons[i].classList.toggle("on", boutons[i].getAttribute("data-tube") === t);
    }
    try { localStorage.setItem("agnt.tube", t); } catch (e) { /* sans stockage, sans Importance */ }
  }
  try {
    var sauve = localStorage.getItem("agnt.tube");
    if (sauve) poser(sauve);
  } catch (e) { /* ok */ }
  var boite = document.getElementById("tubes");
  if (boite) boite.addEventListener("click", function (ev) {
    var b = ev.target && ev.target.closest ? ev.target.closest("button[data-tube]") : null;
    if (b) poser(b.getAttribute("data-tube"));
  });

  /* 2 · allumage du tube au lancement d'un run */
  var run = document.getElementById("run");
  var boot = document.getElementById("boot");
  if (run && boot) run.addEventListener("click", function () {
    if (run.disabled) return;
    boot.className = "on";
    setTimeout(function () { boot.className = "on eteint"; }, 620);
    setTimeout(function () { boot.className = ""; }, 1150);
  });

  /* 3 · le point canal lit l'état écrit par app.js (#etat), jamais l'inverse */
  var etat = document.getElementById("etat");
  var canal = document.getElementById("canal");
  if (etat && canal && typeof MutationObserver === "function") {
    var lit = function () {
      canal.classList.toggle("vif", /en_cours|envoi/.test(etat.textContent || ""));
    };
    new MutationObserver(lit).observe(etat, { childList: true, characterData: true, subtree: true });
    lit();
  }
})();
