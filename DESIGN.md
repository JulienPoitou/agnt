# DESIGN.md — le langage « salle de contrôle analogique »

Ce document est le **contrat de design** de l'interface AGNT. Toute nouvelle surface
(console, écran de rapport, page de doc) s'y conforme. Il existe pour une raison précise :
sans décision écrite, chaque écran retombe dans la médiane statistique — dégradés violets,
verre dépoli, pilules arrondies — le look « généré » que ce projet refuse.

Référence implémentée : `PHASE3/interface/` (console) · démo d'exploration : hors dépôt.

## Le concept en une phrase

**Le dossier de mission est une page imprimée ; le résultat est un tube cathodique.**
Deux matières, jamais mélangées : papier os + encre pour ce qui se déclare, phosphore
monochrome pour ce qui se mesure.

## Les interdits (tells du design généré)

1. **Aucun dégradé décoratif.** Ni violet→bleu, ni halo, ni « glow ». Les trames (scanlines,
   grain) sont des aplats répétés, pas des dégradés.
2. **Aucun `border-radius`.** Tout est carré ; `border-radius: 0 !important` est en place.
3. **Aucune ombre portée floue, aucun `backdrop-filter`.** La profondeur vient des filets
   1px et des inversions (texte/fond échangés), pas d'une illusion de verre.
4. **Aucun emoji comme icône.** États et marqueurs sont typographiques : `■ □ ▮ ✓ ✖ ▲ ·`.
5. **Pas d'indigo/violet en accent.** L'accent unique est l'orange sécurité `#FF4E00`,
   réservé à l'alerte et à l'action critique — jamais décoratif.
6. **Pas de métrique inventée.** Un chiffre affiché vient d'un artefact du moteur ; « absent »
   s'affiche comme absent (`?` / bloc non rendu), jamais comme 0.
7. **Pas de carte arrondie à bordure gauche colorée** (la forme canonique de la tuile IA) :
   les découvertes sont des **rangées réglées** avec code sévérité typographique.

## Les tokens

### Tubes (phosphore) — l'habillage change, la machine reste
| tube | fond | phosphore | clair | tamisé |
|---|---|---|---|---|
| P3 · ambre (défaut) | `#0e0b04` | `#ffb000` | `#ffd75e` | `#9a7a2a` |
| P1 · verde | `#040a06` | `#35e878` | `#8cffb8` | `#2a7a4c` |
| P4 · blanc | `#07080a` | `#dee5ec` | `#ffffff` | `#6e7a88` |

Filets : le phosphore à 26-28 % d'alpha. Panneau : un pas plus clair que le fond.

### Sévérité — fixe, ne suit pas le tube
`critique #ff4e00` · `erreur #ff6b4a` · `haute #ffb000` · `moyenne #e0c36a` · `basse #8a93a6`

### Typographie
- **Archivo** (variable, condensé 72-78 %, poids 900, majuscules) : titres de surface.
- **IBM Plex Mono** : TOUTES les données, labels, tableaux, journal. Rien d'autre.
- **Instrument Serif italique** : une seule ligne éditoriale par écran, pas plus.

Échelle : labels 9-10px, espacement .14-.2em, MAJUSCULES ; données 11-13px ; chiffres
forts 26px tabulaires ; display 30px+ (page pleine : jusqu'à 108px).

### Motion
- `steps()` pour les effets CRT (allumage, flicker) — mécanique, pas élastique.
- Transitions 120-300ms, `cubic-bezier(.2,0,.4,1)` — apparu, pas « glissé ».
- Curseur bloc clignotant `steps(1)`. Balayages en rotation pure, traînée en n segments
  d'alpha décroissant (pas de flou).
- L'allumage du tube (ligne horizontale → extinction) marque le passage brief → mission.

## La texture

Scanlines : `repeating-linear-gradient(0deg, rgba(0,0,0,.18) 0 1px, transparent 1px 3px)`.
Grain : SVG `feTurbulence` en data-URI, alpha ≈ .04. Deux trames plates, superposées,
`pointer-events: none` — c'est l'unique « effet » du système.

## Honnêteté d'affichage (non négociable, plus fort qu'un choix de style)

- `textContent` partout, jamais `innerHTML` (le contenu d'un outil a lu un dépôt hostile).
- Un champ absent du moteur est absent de l'écran ; la maquette est un repli **affiché
  comme tel** (bandeau MAQUETTE), jamais un avant-goût peint avant vérification.
- Le cosmétique (`console.js`) ne lit aucune API et n'invente aucun chiffre : le compteur
  de vitesse « 0.57c » des démos n'a PAS sa place dans la console réelle.
