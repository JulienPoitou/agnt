# Câble chat→moteur (engagement web) — check-list anti-boucle

Règle de session : **commencer à la première case NON cochée.** Rien de déjà coché
ne se re-qualifie ni ne se re-teste — les preuves vivent dans
`PHASE3/cible_web/qualif/` (`DOSSIER_web.yaml` + `ATTENDUS_SANDBOX.yaml`) et dans
les batteries de ce dépôt : on s'y réfère, on ne les refait pas.

## ① Le câble (de la console aux findings réels)

- [x] ①-a `POST /api/engagements/web` branché au cockpit : plan + statut réels à
      l'écran (section « Engagement web » de la console) — 2026-09-05
- [x] ①-b tranche **httpx** : `executer: true` → file → `pipeline_web.derouler` →
      `ExecuteurLocal` → findings OBSERVED affichés + `rapport_web.json` scellé
      (batterie machine de référence : `PHASE3/test_web_cable.py`) — 2026-09-05
- [x] ①-b tranche **ffuf** : tourne dans la chaîne au cockpit (wordlist épinglée
      `{REGLES}/dossiers-mini.txt`) — démo 2026-09-05 : `admin` et `.env` confirmés 3/3
- [x] ①-b tranche **nuclei** : tourne dans la chaîne au cockpit (template local
      épinglé `{REGLES}/nuclei-epreuve.yaml`) — démo 2026-09-05 : `epreuve-thaumas-info` confirmé
- [x] **oracle** : branché dans `pipeline_web` (`_rejouer`) — rejeu RÉEL ×N
      (3 normal / 5 aggressive) + témoin (chemin aléatoire du même hôte) ;
      recette = statut déclaré quand le tool en porte un, sinon « stabilité »
      (anti-soft-404) ; CONFIRMED → candidater + verifier_ok (VERIFIED),
      REFUTED → rejeter (REJECTED), POTENTIAL/INCONCLUSIVE → reste OBSERVED
      avec la raison ; hors scope = pas de rejeu (raison nommée) ;
      test_web_cable 12/12, démo : 4/4 vérifiés — 2026-09-05
- [x] **correspondance IA** : chat BYOK (Groq) dans la console — parle librement
      de tout, peut PROPOSER un engagement via appel d'outil, CONFIRMATION
      HUMAINE obligatoire (le clic est l'attestation cible_autorisee), explique
      les constats rendus par le moteur (jamais inventés) ; clé + consigne
      permanente éditables, localStorage navigateur — 2026-09-05
- [x] **G2 vague-web/g2 — katana, gobuster, feroxbuster, dirsearch, hakrawler**
      (2026-09-05) : 5/5 qualifiés (preuves qualif/, batteries test_plugins_g2
      94/94 sans réseau, parsers gobuster/feroxbuster/hakrawler-wrapper) ;
      intégration main : merge + promotion des binaires staging→bin/ avec
      contrôle d'empreinte contre les épingles (c'est l'ÉTAPE D'INTÉGRATION
      CENTRALISÉE : les agents installent en staging, seul l'intégrateur
      expose au runtime) ; démo : chaîne httpx→katana→ffuf→nuclei = 8
      constats, diff reprise 1 persistant/7 nouveaux puis 8/8 stationnaire
- [x] **G4 vague-web/g4 — testssl.sh, sslyze, sslscan, tlsx, dotdotpwn**
      (2026-09-05) : 5/5 qualifiés (batterie test_plugins_g4 50/50) ;
      **dotdotpwn a trouvé T-TRAVERSAL-001** (14 traversals vulnérables,
      code_succes 105 mesuré dans la source) ; outils TLS : refus nommés
      mot pour mot sur cible non-TLS (épreuve honnête) ; intégration : merge +
      promotion bin/ + wrapper dotdotpwn rendu symlink-safe (readlink -f,
      épingle mise à jour) + id corrigé testssl_sh ; **chaîne : 13 providers,
      12 réels, 23 constats en un engagement** ; restent SQLi (sqlmap) et XSS
      (dalfox) — G3 en vol
- [x] **G1 vague-web/g1 — whatweb, webanalyze, wafw00f, nikto** (2026-09-05,
      commit 6d5315e rebase propre) : 4/5 qualifiés (batterie
      test_plugins_g1 101/101) ; gowitness REFUSÉ nommément (chrome absent,
      canal hors règles, image non projetable — refus vérifié par la
      batterie) ; nikto retrouve /.env, /.git, bannière obsolète + en-têtes
      (11 constats) ; corrections du travail de l'agent tué (JSON invalide
      régénéré, webanalyze location.url via lecture imbriquée) ; wrapper
      nikto_scan symlink-safe + PERL5LIB perl_lib/usr/share/perl5 ; id
      provider `nikto` (le wrapper porte le suffixe) ; **intégration :
      22/22 providers dans le détail, 0 écarté, 0 hors cage, 33 constats,
      26 VERIFIED par 15 outils**
- [x] **G3 vague-web/g3 — sqlmap, dalfox, commix, crlfuzz, arjun**
      (2026-09-05) : 5/5 qualifiés (batterie test_plugins_g3 58/58) ;
      **sqlmap trouve T-SQLI-001** (3 techniques : boolean blind, time blind,
      UNION — toutes VERIFIED par l'oracle après relève du plafond stdout
      4000→20000, le journal coupait la ligne cible) ; **dalfox trouve
      T-XSS-001** (sévérité High DÉCLARÉE, CWE-79, VERIFIED) ; commix/crlfuzz :
      résultats vides HONNÊTES motivés ; arjun découvre le paramètre q ;
      intégration : merge + wrappers symlink-safe + promotion + épingles.
- [x] **★ CRITÈRE D'ARRIVÉE ATTEINT — 9/9 failles de THAUMAS-WEB détectées et
      confirmées par l'oracle** (2026-09-05) : T-SRV-001 bannière (httpx) ·
      T-ENV-001 /.env (ffuf, gobuster, feroxbuster, dirsearch) · T-GIT-001/002
      /.git (ffuf, feroxbuster + git-dumper) · T-ADMIN-001 /admin (idem) ·
      T-TRAVERSAL-001 (dotdotpwn) · T-SQLI-001/002 (sqlmap) · T-XSS-001
      (dalfox) — le tout SOUS CAGE bwrap, preuve scellée par engagement,
      reprise diff stable.
- [x] **G5 vague-web/g5 — kiterunner, gospider, dirhunt, x8, cmseek**
      (2026-09-05, commit b9f8900) : 5/5 — wpscan REFUSÉ nommément (ruby-dev
      absent, mesuré) et REMPLACÉ par cmseek pour la capacité audit CMS ;
      kiterunner trouve /.env et /admin (chemins NON liés — complément exact
      des crawlers) ; dirhunt : 3 limites d'outil mesurées et nommées ; x8 :
      vide motivé (chasse les paramètres cachés, q est visible) ; intégration :
      merge + promotion + 27/27 providers dans le détail, 0 écarté, 0 hors
      cage, 43 constats, 36 VERIFIED par 18 outils ; reprise 32 persistants /
      10 nouveaux / 1 non relevé
- [x] **★ VAGUE COMPLÈTE — 27 providers qualifiés et actifs dans la chaîne en
      phases** (surface 4 · endpoints 11 · vuln 12), tous SOUS CAGE bwrap,
      épinglés, promus, testés (batteries g1-g5 : 101+94+58+50+57 cas)
- [x] **★ CIBLE HTTPS D'ÉPREUVE — les 4 outils TLS prouvés POSITIVEMENT** (2026-09-05,
      fin des refus nommés comme seule épreuve) : `serveur.py --tls` (certificat
      auto-signé GÉNÉRÉ AU BOOT via openssl dans certs/ gitignoré, CN=thaumas-web-epreuve,
      handshake par connexion — une sonde HTTP pur ne tue pas le serveur, multi-slash
      normalisés) ; jeton `{HOSTPORT}` dans le cœur (fournisseurs_web._hote_port : port
      par défaut du schéma RESTAURÉ — sslscan/sslyze refusent les URL, mesuré) ;
      manifests requalifiés (sslscan/sslyze en {HOSTPORT}, mapping tlsx CORRIGÉ sur
      structure réelle : `cipher` PAS `cipher_suite`, probe_status booléen) ;
      **sslyze : --certinfo volontairement hors manifeste** (le PEM déclenche le
      masquage des blobs base64 ≥ 40 qui rend le JSON capturé illisible → 0 item,
      mesuré et assumé — capacité complète prouvée hors manifeste dans
      sslyze_complet.json, 15 constats réels sur 18 commandes, result None écartés
      par le parser) ; archives qualif/*_https.* + attendus_tls.yaml ×4 +
      executer_qualif_tls.py ; **démo réelle SOUS CAGE : engagement https://127.0.0.1:8443
      → 185 constats TLS (sslscan 18, testssl.sh 166 avec sévérités déclarées dont
      CRITICAL cert_chain_of_trust sur auto-signé, tlsx tls13/CN)** ; batterie
      test_plugins_g4 69/69
- [x] **★ SCAN AUTHENTIFIÉ v1 (cookie)** — le trou n°1 du bilan est BOUCHÉ (2026-09-05) :
      `POST /api/engagements/web` accepte `auth_cookies` (SECRET : jamais rendu par
      l'API, jamais dans ETATS, jamais dans la preuve scellée — la VALEUR transite par
      les options de file → derouler(auth_cookies=…), testé en batteries) ; injection
      PAR MANIFEST opt-in `{COOKIES}` (httpx/nuclei/katana/dalfox en -H « Cookie: … »,
      sqlmap/dirsearch --cookie=, ffuf -b, gobuster --cookies — flags vérifiés au
      --help des binaires épinglés ; les 4 TLS et whatweb restent non déclarants, NOMMÉS
      au rapport) ; sans cookie fourni la paire flag/arg-vide est retirée DÉTERMINISTE-
      MENT (Tache exige des chaînes non vides — un arg {COOKIES} vide est inconstructible)
      ; THAUMAS gagne T-AUTH-001/002 (POST /login → Set-Cookie SESSION générée au boot ;
      /admin/secret-session : 302 sans cookie, 200 + secret factice avec ; IDOR
      ?user=oscar ; lien Sessions sur /admin pour la découvrabilité) ; **ÉPREUVE DE
      VALEUR ×2 mesurée** (ffuf -fc 302 filtre la frontière d'auth, wordlist
      admin/secret-session) : engagement A sans cookie (68e9174a1b2b : 4 constats,
      secret-session INVISIBLE) → engagement B avec cookie (f48e8003b3ec : 5 constats,
      /admin/secret-session **VERIFIED oracle confirmed**, reprise : +1 nouveau) ;
      **oracle authentifié** : le rejeu porte le cookie de l'engagement (sans lui il
      réfute ce que l'outil a réellement vu — mesuré) ; **non-fuite prouvée** : ffuf
      écho sa commandline dans son propre JSON de sortie → les sorties brutes du run
      sont masquées avec la valeur DÉCLARÉE (examiner valeurs=…), token absent de
      GET /api/runs ET de tous les artefacts disque ; batteries : test_web_auth 27/27
      (nouveau), test_engagements_web 40/40, test_pipeline_web 22/22, test_web_cable
      14/14, test_cible_auth 8/8 (nouveau), g1-g3 inchangées
- [ ] ①-b tranche **git-dumper** : hors `WEB_PROVIDERS_ORDRE` (découverte ≠ sonde) —
      décider de son entrée dans la chaîne (provider d'appoint ? capacité à part ?)
- [x] **corrélation — étude** : `docs/RECHERCHE_CORRELATION.md` (Burp, ZAP,
      DefectDojo, Faraday, GitLab, Nuclei, Semgrep, PentestGPT/PentAGI/XBOW,
      SSVC/EPSS — mécanismes exacts + 10 patterns transposables + 10
      recommandations impact/effort) — 2026-09-05
- [x] **corrélation — implantation v1, empreinte + diff de re-scan** (2026-09-05) :
      l'empreinte `identity.fingerprint` est déjà STABLE inter-runs (mesuré :
      deux engagements httpx consécutifs → même empreinte) ; diff branché
      (`pipeline_web._diff_reprise` + `_engagement_precedent` dans api.py) —
      persistants / nouveaux / non_releves dans `rapport.reprise`, affiché au
      cockpit et rendu au chat ; « non relevé » est un FAIT rendu, jamais un
      verdict corrigé (pas de transition cycle_vie sans preuve — leçon DefectDojo)
- [x] **corrélation — seconde recette pour VERIFIED** (2026-09-05, leçon XBOW) :
      `extraction.champs` accepte `extrait_corps: <champ>` — le manifest déclare
      un token attendu DANS le corps (httpx : le titre) ; routé vers
      `evidence.extrait_attendu` ; l'oracle l'exige en plus du statut à CHAQUE
      rejeu (et le témoin ne doit pas l'avoir) ; corps sans le token → rejeu
      partiel → POTENTIAL → reste OBSERVED (dégradation honnête). Mesuré live :
      titre déclaré, présent 3/3, témoin propre. test_web_cable 13/13
- [x] **corrélation — plafond SYSTEMIC** (2026-09-05, leçon ZAP 2.17) :
      `pipeline_web._systemique` — une même règle d'un même outil au-delà de
      5 URLs distinctes devient UN agrégat dans `rapport.systemique`
      (occurrences, URLs distinctes, échantillon de 5, troncature affichée) ;
      les findings restent intacts (empreintes → diff de re-scan) ; bloc
      « Motifs systémiques » au cockpit. test_pipeline_web 15/15
- [ ] **corrélation — fin** : identifiant primaire (CVE/GHSA > règle
      canonique > empreinte, leçon GitLab) — mineur tant que les outils web
      n'émettent pas de CVE ; vers `clusterer.py` quand le volume l'exigera
- [x] **cage** : exécution web SOUS CAGE bwrap au runtime (2026-09-05,
      commit cd022c6) — `pipeline_web.ExecuteurCage` assemble `slice/sandbox.py`
      (`cible_distante=True`, machinerie du harnais assemblée pas dupliquée) ;
      {BIN} résolu en chemin hôte (bwrap n'a pas de lookup PATH interne),
      `verifie()` avant chaque lancement (refus nommé sinon), traduction
      hôte→cage OBLIGATOIRE pour {OUT}/{REGLES} (sans elle : écriture dans un
      / ro → code 1 muet, mesuré), garde anti-double-cage sur les relances ;
      cage=True par défaut, drapeau par provider dans les détails ; démo :
      13 providers cage=True partout, 26 constats. unitaires 18/18,
      test_web_cable 14/14 (httpx réel sous bwrap)

## ② Qualifications sandbox — TERMINÉ ✅ (ne pas refaire)

httpx, git-dumper, nmap, nuclei, ffuf : preuves d'exécution réelle sous bwrap 0.9.0
(egress accordé), stabilité contenu normalisé, findings attendus relus —
`PHASE3/cible_web/qualif/DOSSIER_web.yaml`. Bug produit trouvé au passage :
manifeste ffuf sans `-w` (inutilisable depuis l'origine) + placeholders `0.1.0`
écrasant les épinglages — corrigé et épinglé dans `manifeste_dependances.yaml`.

## ③ Vague scanners — GELÉE

Ajout des ~14 scanners web manquants au registre : interdit tant que ① n'est pas
démo-complet (chaîne au cockpit + oracle). Après quoi, une vague = des manifests +
une tranche batterie chacun, jamais de re-test global.
