# BILAN A→Z — le système web AGNT au 2026-09-05

Ce que fait le système, ce qui a été construit, ce qui manque. Document de
référence — à mettre à jour, pas à refaire (règle anti-boucle).

---

## 1. LE FLUX A→Z, CE QUI SE PASSE QUAND TU LANCES (tout est ✅)

1. ✅ **Console** : `http://127.0.0.1:8141` — moteur branché, 0.2 s au chargement.
2. ✅ **Section « Engagement web »** : tu colles l'URL, tu coches autorisation
   (attestation légale, fail-closed) + cage réseau + exécution réelle.
3. ✅ **Chat « Correspondance »** : tu peux DEMANDER au chat de lancer le scan
   (« scanne http://… ») — l'IA propose, TU confirmes d'un clic ; elle explique
   ensuite les constats réels du moteur, jamais inventés.
4. ✅ **Plan** : 27 providers en 3 phases (surface → endpoints → vuln), débits
   déclarés, ordre garanti, rendu à l'écran avant exécution.
5. ✅ **File à un consommateur** : une exécution à la fois, tolérante aux échecs
   (un outil mort n'arrête plus la chaîne — échec nommé, run continue).
6. ✅ **Exécution SOUS CAGE bwrap** de chaque outil : binaire épinglé (sha256),
   montages réels, egress selon l'engagement, refus nommés si la cage refuse.
7. ✅ **27 détecteurs qualifiés** (voir §3) — production par 5 agents parallèles,
   chaque outil : binaire épinglé + manifest + parser + épreuve réelle + batterie.
8. ✅ **Interprétation déclarative** : manifests → findings normalisés (règle,
   titre, message, URL, CWE, payload…) — le cœur ne devine rien.
9. ✅ **ORACLE** : rejeu réel ×3 (×5 aggressive) + témoin anti-soft-404 +
   seconde recette (`extrait_corps` déclaré au manifest) → VERIFIED /
   REFUTED / reste OBSERVED avec raison. Aucun corps conservé (digest+taille).
10. ✅ **Corrélation v1** : empreinte stable inter-runs → diff de re-scan
    (persistants / nouveaux / non relevés — un fait, jamais « corrigé ») +
    plafond SYSTEMIC (motif répété >5 URLs = un agrégat, troncature affichée).
11. ✅ **Rapport au cockpit** : mission header, ce qui a tourné (détail par
    provider, drapeau cage), constats avec sévérité/origine, motifs systémiques,
    preuve scellée, archive disque.
12. ✅ **Preuve scellée** : empreinte sha256 vérifiable (`preuve.verifier`).
13. ✅ **Archives disque** : `artifacts/engagements/<id>/` — sorties brutes des
    outils + `rapport_web.json` + `journal.jsonl` + preuve. Survit aux
    redémarrages (éprouvé : le WSL a redémarré en plein run, tout est réapparu).
14. ✅ **Diff de re-scan** : relancer sur la même cible → persistants /
    nouveaux / non relevés, rattaché à l'engagement précédent.
15. ✅ **CI** : lint + tests + compile + gitleaks 8.30.1 épinglé (checksum
    binaire vérifié). Verte.

## 2. LES 27 DÉTECTEURS ACTIFS (tous sous cage, épinglés, testés)

**Surface (4)** : httpx (bannière+titre+tech) · whatweb (techno détaillée) ·
webanalyze (techno via en-têtes) · wafw00f (détection WAF)
**Endpoints (11)** : katana (crawl) · ffuf (fuzz dossiers) · gobuster ·
feroxbuster · dirsearch · hakrawler (crawl léger) · arjun (params cachés) ·
x8 (params cachés, complément) · kiterunner (API) · gospider (crawl) ·
dirhunt (répertoires)
**Vuln (12)** : nuclei (templates) · sqlmap (**SQLi prouvée, 3 techniques**) ·
dalfox (**XSS, sévérité déclarée**) · commix (injection cmd) · crlfuzz (CRLF) ·
dotdotpwn (**traversal prouvé**) · testssl.sh · sslyze · sslscan · tlsx (TLS ×4)
· nikto (8 000+ tests, en-têtes/fichiers sensibles) · cmseek (audit CMS)

Refus documentés (doctrine) : gowitness (chrome absent, image non projetable) ·
wpscan (ruby-dev absent — remplacé par cmseek).

**Critère d'arrivée : ✅ 9/9 failles de THAUMAS-WEB détectées ET confirmées par
l'oracle** — bannière, /.env, /.git ×2, /admin, XSS, SQLi ×2, traversal.

## 3. CE QUI A ÉTÉ CONSTRUIT AUJOURD'HUI (chronologique)

| Livraison | Contenu |
|---|---|
| Portage qualif (4ff6866) | 27 manifests web + cible THAUMAS + preuves bwrap + parsers |
| Câblage exécution | `executer:true` → file → pipeline_web réel → archives |
| Oracle (1bab76d) | rejeu ×N + témoin + cycle de vie → VERIFIED |
| Correspondance IA | chat BYOK branché au moteur, confirmation humaine |
| CI fix (1fb21ce) | gitleaks ré-épinglé (l'action ignorait sa version) |
| Corrélation v1 (408f8d6…) | empreinte stable + diff de re-scan + SYSTEMIC |
| Seconde recette (9d76afe) | `extrait_corps` — confirmé exige 2 signaux |
| Vague 5 agents | 15 nouveaux outils qualifiés (G1-G5, 5 batteries : 360 cas) |
| Chaîne en phases (9a2b046) | surface→endpoints→vuln + tolérance aux échecs |
| CAGE runtime (cd022c6) | chaque outil sous bwrap, traduction chemins, refus nommés |
| Perf registre | mémoïsation — 26 s → 0,13 s (×200) à 27 providers |
| Veille corrélation | DefectDojo/Burp/ZAP/XBOW → 10 recommandations implantées |

**État git** : main à jour, CI verte, ~30 commits sur la journée, mémoire et
check-list (`docs/CABLE_WEB.md`) à jour.

## 4. CE QUI MANQUE POUR LE « A→Z MÉTIER » COMPLET (honnête)

1. ✅ **Scan authentifié v1 (cookie)** — BOUCHÉ le 2026-09-05 : `auth_cookies` dans
   l'engagement (jamais rendu, jamais scellé, jamais sur disque — testé), injection
   opt-in `{COOKIES}` par manifest (8 outils, flags vérifiés au --help), THAUMAS gagne
   T-AUTH-001/002 (session factice + IDOR), ÉPREUVE DE VALEUR ×2 mesurée (sans cookie :
   la ressource protégée est invisible ; avec : constaté puis VERIFIED par l'oracle
   authentifié, diff de re-scan +1). Reste pour v2 : login form multi-étapes, sessions
   applicatives complexes (CSRF, JWT, rafraîchissement), credentials utilisateur/pass
   au-delà du cookie brut.
2. ❌ **Rapport humain exportable** : les engagements rendent `rapport_web.json`
   + console, pas de RAPPORT.md/PDF final signé comme les missions dépôt.
3. ✅ **Épreuve TLS positive** — FAITE le 2026-09-05 : la cible a un mode `--tls`
   (certificat auto-signé généré au boot, CN=thaumas-web-epreuve) ; jeton `{HOSTPORT}`
   dans le cœur ; sslscan 18 items (TLS 1.2/1.3 + 16 suites), testssl.sh 166 entrées
   (sévérités DÉCLARÉES, CRITICAL sur chaîne auto-signée), tlsx 1 JSONL (mapping
   corrigé sur structure réelle), sslyze 6 commandes runtime (`--certinfo` volontaire-
   ment hors manifeste : le PEM déclenche le masquage qui rend le JSON illisible —
   capacité complète prouvée hors manifeste). Démo réelle SOUS CAGE : 185 constats TLS.
4. ❌ **Qualification bwrap par outil** : les épreuves G1-G5 ont tourné hors
   cage ; la cage runtime est branchée, la preuve qualif sous cage par outil
   reste « à centraliser » (le harnais_web existe).
5. ❌ **Profondeur d'exploitation** : sqlmap/dalfox prouvent SQLi/XSS, mais pas
   d'escalade automatique (dump de base, prise de session) — choix de doctrine,
   à cadrer.
6. ❌ **Identifiant primaire CVE/GHSA + priorisation EPSS/SSVC** (mineur, à
   volume).
7. ❌ **Bootstrap WSL complet** (3,7 Go : semgrep/SAST) — décision, C: 96 %.
8. ❌ **Élargissement au-delà de la spec v1** : Awesome-Hacking 64/129 — les
   vagues suivantes (recon passive, API GraphQL, mobilité…) restent ouvertes.

## 5. VERDICT A→Z

- **Cible HTTP autorisée, non authentifiée, sur ta machine/lab** : **OUI, A→Z** —
  de l'URL tapée aux constats vérifiés, expliqués par l'IA, archivés, scellés,
  comparables entre eux. C'est démontré, pas promis.
- **Cible HTTP/HTTPS d'épreuve AUTORISÉE, authentifiée par cookie** : **OUI, A→Z** —
  l'épreuve de valeur ×2 (sans cookie : invisible ; avec : constaté et confirmé par
  l'oracle) est mesurée, archivée, scellée.
- **Pentest professionnel complet (authentifications complexes, rapport client,
  exploitation profonde, TLS de production)** : **pas encore** — points restants du §4.
- **Le chemin** : chaque ❌ du §4 est un chantier borné, dans l'ordre : rapport
  exportable > qualif bwrap centralisée > authentifications complexes.
