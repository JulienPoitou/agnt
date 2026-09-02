# AGNT — Catalogue Web Providers — 119 outils (13 catégories)

> Source : `enaqx/awesome-pentest` (91KB, 37 sections) — extraction exhaustive 119 outils web.
> Branche `feat/web-pentest-console-v1` — `main` gelé à `a7ec46f`.
> Chaque outil = 1 plugin potentiel `PHASE3/plugins/<outil>.yaml` → `Findings.location.url` → `Oracle http_response`.

---

## 1. Recon WEB — Network Reconnaissance Tools — 26 outils

| Outil | URL | Description |
|---|---|---|
| ACLight | https://github.com/cyberark/ACLight | Découverte comptes privilégiés Shadow Admins |
| AQUATONE | https://github.com/michenriksen/aquatone | Découverte sous-domaines, rapport exploitable |
| CloudFail | https://github.com/m0rtem/CloudFail | Dévoile IP derrière Cloudflare |
| DNSDumpster | https://dnsdumpster.com/ | Recon DNS en ligne |
| masscan | https://github.com/robertdavidgraham/masscan | Scanner TCP SYN async, Internet <5min |
| OWASP Amass | https://github.com/OWASP/Amass | Énumération sous-domaines (scraping, bruteforce, certs TLS) |
| ScanCannon | https://github.com/johnnyxmas/ScanCannon | BASH chain masscan → nmap |
| XRay | https://github.com/evilsocket/xray | Découverte (sub)domain |
| dnsenum | https://github.com/fwaeytens/dnsenum/ | Enum DNS, zone transfer |
| dnsmap | https://github.com/makefu/dnsmap/ | Mapper DNS passif |
| dnsrecon | https://github.com/darkoperator/dnsrecon/ | Enum DNS |
| dnstracer | http://www.mavetju.org/unix/dnstracer.php | Chaîne serveurs DNS source |
| fierce | https://github.com/mschwager/fierce | Localisation IP non-contigu |
| netdiscover | https://github.com/netdiscover-scanner/netdiscover | Scanner ARP |
| nmap | https://nmap.org/ | Scanner audit réseau |
| passivedns-client | https://github.com/chrislee35/passivedns-client | Query Passive DNS |
| passivedns | https://github.com/gamelinux/passivedns | Sniffer DNS |
| RustScan | https://github.com/rustscan/rustscan | Scanner ports → pipe Nmap |
| scanless | https://github.com/vesche/scanless | Scan ports via sites web (IP masquée) |
| smbmap | https://github.com/ShawnDEvans/smbmap | Enum SMB |
| subbrute | https://github.com/TheRook/subbrute | Spider DNS |
| zmap | https://zmap.io/ | Scanner Internet-wide |
| Have I Been Squatted | https://haveibeensquatted.com | Typosquatting |
| Subfinder | https://github.com/projectdiscovery/subfinder | Enum passive sous-domaines |
| Naabu | https://github.com/projectdiscovery/naabu | Scanner ports Go |
| Katana | https://github.com/projectdiscovery/katana | Crawling & spidering |

## 2. Scanners WEB — Web Vulnerability Scanners — 19 outils

| Outil | URL | Description |
|---|---|---|
| ACSTIS | https://github.com/tijme/angularjs-csti-scanner | CSTI AngularJS |
| Arachni | http://www.arachni-scanner.com/ | Framework évaluation web app |
| JCS | https://github.com/TheM4hd1/JCS | Vuln Joomla |
| Nikto | https://github.com/sullo/nikto | Scanner bruit rapide |
| SQLmate | https://github.com/UltimateHackers/sqlmate | SQLi via dork |
| SecApps | https://secapps.com/ | Suite test dans navigateur |
| WPScan | https://wpscan.org/ | Vuln WordPress |
| Wapiti | http://wapiti.sourceforge.net/ | Black-box + fuzzer |
| WebReaver | https://www.webreaver.com/ | Scanner macOS |
| cms-explorer | https://code.google.com/archive/p/cms-explorer/ | Modules CMS |
| joomscan | https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project | Vuln Joomla |
| skipfish | https://www.kali.org/tools/skipfish/ | Recon actif performant |
| w3af | https://github.com/andresriancho/w3af | Framework attaque web |
| WAFtester | https://github.com/waftester/waftester | Fingerprint 197+ WAF, 70+ évasions |
| nuclei | https://github.com/projectdiscovery/nuclei | Scanner DSL YAML (prioritaire AGNT) |
| Lonkero | https://github.com/bountyyfi/lonkero | 60+ modules Rust |
| jiraffe | https://github.com/0x48piraj/jiraffe | Recon Jira |
| Dalfox | https://github.com/hahwul/dalfox | XSS param |
| Ghauri | https://github.com/r0oth3x49/ghauri | SQLi avancé |

## 3. Fingerprint — Web Application and Resource Analysis Tools — 9 outils

| Outil | URL | Description |
|---|---|---|
| BlindElephant | http://blindelephant.sourceforge.net/ | Fingerprinter web app |
| EyeWitness | https://github.com/ChrisTruncer/EyeWitness | Screenshots + headers + creds défaut |
| GraphQL Voyager | https://graphql-kit.com/graphql-voyager/ | Graphe GraphQL |
| VHostScan | https://github.com/codingo/VHostScan | Vhosts |
| Wappalyzer | https://www.wappalyzer.com/ | Tech detect |
| WhatWaf | https://github.com/Ekultek/WhatWaf | Détecte & bypass WAF |
| WhatWeb | https://github.com/urbanadventurer/WhatWeb | Fingerprinter |
| wafw00f | https://github.com/EnableSecurity/wafw00f | Fingerprint WAF |
| webscreenshot | https://github.com/maaaaz/webscreenshot | Screenshots liste |

## 4. Proxies MITM — Proxies and MITM Tools — 14 outils

| Outil | URL | Description |
|---|---|---|
| BetterCAP | https://www.bettercap.org/ | Framework MITM |
| Ettercap | http://www.ettercap-project.org | Suite MITM |
| Habu | https://github.com/portantier/habu | ARP poisoning etc. |
| Lambda-Proxy | https://github.com/puresec/lambda-proxy | SQLi Lambda |
| MITMf | https://github.com/byt3bl33d3r/MITMf | MITM |
| Morpheus | https://github.com/r00t-3xp10it/morpheus | Hijacking TCP/IP |
| SSH MITM | https://github.com/jtesta/ssh-mitm | Proxy SSH |
| dnschef | https://github.com/iphelix/dnschef | Proxy DNS |
| evilgrade | https://github.com/infobyte/evilgrade | Fausses MAJ |
| mallory | https://github.com/justmao945/mallory | HTTP/HTTPS over SSH |
| oregano | https://github.com/nametoolong/oregano | MITM Tor |
| sylkie | https://dlrobertson.github.io/sylkie/ | Spoofing IPv6 |
| PETEP | https://github.com/Warxim/petep | Proxy TCP/UDP extensible |
| friTap | https://github.com/fkie-cad/friTap | Interception SSL/TLS frida |

## 5. Interception Web — Intercepting Web Proxies — 4 outils

| Outil | URL | Description |
|---|---|---|
| Burp Suite | https://portswigger.net/burp/ | Référence test web |
| Fiddler | https://www.telerik.com/fiddler | Proxy debug |
| OWASP ZAP | https://www.zaproxy.org/ | Proxy + fuzzer |
| mitmproxy | https://mitmproxy.org/ | Proxy interactif TLS |

## 6. TLS/SSL — Transport Layer Security Tools — 6 outils

| Outil | URL | Description |
|---|---|---|
| CryptoLyzer | https://gitlab.com/coroner/cryptolyzer | Analyse crypto |
| SSLyze | https://github.com/nabla-c0d3/sslyze | Config TLS/SSL |
| crackpkcs12 | https://github.com/crackpkcs12/crackpkcs12 | Cracker .p12 |
| testssl.sh | https://github.com/drwetter/testssl.sh | Ciphers/protocols |
| tls_prober | https://github.com/WestpointLtd/tls_prober | Fingerprint SSL/TLS |
| tlsmate | https://gitlab.com/guballa/tlsmate | Cas tests TLS |

## 7. Exploit Web — Web Exploitation — 9 outils

| Outil | URL | Description |
|---|---|---|
| FuzzDB | https://github.com/fuzzdb-project/fuzzdb | Dictionnaire patterns |
| OWTF | https://www.owasp.org/index.php/OWASP_OWTF | Framework OWASP |
| Raccoon | https://github.com/evyatarmeged/Raccoon | Recon & vuln scanning |
| WPSploit | https://github.com/espreto/wpsploit | Exploit WordPress via Metasploit |
| autochrome | https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/march/autochrome/ | Profil Chrome pentest |
| authoscope | https://github.com/kpcyrd/authoscope | Cracker auth |
| gobuster | https://github.com/OJ/gobuster | Brute force / fuzzing |
| sslstrip2 | https://github.com/LeonardoNve/sslstrip2 | Bypass HSTS |
| sslstrip | https://www.thoughtcrime.org/software/sslstrip/ | Stripping HTTPS |

## 8. LFI/RFI — Web File Inclusion Tools — 4 outils

| Outil | URL | Description |
|---|---|---|
| Kadimus | https://github.com/P0cL4bs/Kadimus | Scan & exploit LFI |
| LFISuite | https://github.com/D35m0nd142/LFISuite | Scanner LFI auto |
| fimap | https://github.com/kurobeats/fimap | LFI/RFI Google |
| liffy | https://github.com/hvqzao/liffy | Exploit LFI |

## 9. Injection — Web Injection Tools — 4 outils

| Outil | URL | Description |
|---|---|---|
| Commix | https://github.com/commixproject/commix | Command injection |
| NoSQLMap | https://github.com/codingo/NoSQLMap | NoSQL injection |
| SQLmap | http://sqlmap.org/ | SQL injection (référence) |
| tplmap | https://github.com/epinna/tplmap | SSTI |

## 10. Fuzz/Brute — Web Path Discovery — 3 outils

| Outil | URL | Description |
|---|---|---|
| DotDotPwn | https://dotdotpwn.blogspot.com/ | Directory traversal |
| dirsearch | https://github.com/maurosoria/dirsearch | Scanner chemins |
| recursebuster | https://github.com/c-sto/recursebuster | Bruteforce récursif |

## 11. Shells C2 — Web Shells and C2 — 7 outils

| Outil | URL | Description |
|---|---|---|
| BeEF | https://github.com/beefproject/beef | C2 navigateurs |
| DAws | https://github.com/dotcppfile/DAws | Web shell avancé |
| Merlin | https://github.com/Ne0nd0g/merlin | C2 HTTP/2 Go |
| PhpSploit | https://github.com/nil0x42/phpsploit | C2 PHP |
| Reverse Shell as a Service | https://github.com/lukechilds/reverse-shell | Reverse shell |
| SharPyShell | https://github.com/antonioCoco/SharPyShell | Webshell ASP.NET |
| weevely3 | https://github.com/epinna/weevely3 | Web shell PHP |

## 12. Source Ripping — Web-accessible Source Code Ripping — 4 outils

| Outil | URL | Description |
|---|---|---|
| DVCS Ripper | https://github.com/kost/dvcs-ripper | Rip SVN/GIT/HG/BZR exposés |
| GitTools | https://github.com/internetwache/GitTools | .git exposés |
| git-dumper | https://github.com/arthaud/git-dumper | Dump git web |
| git-scanner | https://github.com/HightechSec/git-scanner | .git hunting |

## 13. Dorking — OSINT Dorking Tools — 10 outils

| Outil | URL | Description |
|---|---|---|
| BinGoo | https://github.com/Hood3dRob1n/BinGoo | Bing & Google Dorking |
| dorkbot | https://github.com/utiso/dorkbot | Vuln via Google |
| github-dorks | https://github.com/techgaun/github-dorks | Leaks GitHub |
| GooDork | https://github.com/k3170makan/GooDork | Google dorking |
| Google Hacking Database | https://www.exploit-db.com/google-hacking-database/ | Base dorks |
| dork-cli | https://github.com/jgor/dork-cli | CLI Google dork |
| dorks | https://github.com/USSCltd/dorks | Automation |
| fast-recon | https://github.com/DanMcInerney/fast-recon | Dorks domaine |
| pagodo | https://github.com/opsdisk/pagodo | Scraping GHDB |
| snitch | https://github.com/Smaash/snitch | Collecte dorks |

---

## Intégration AGNT V1

- **Priorité P0** (déjà prévus) : `nuclei`, `httpx`, `katana`, `ffuf`/`dirsearch`/`gobuster` (fuzz), `wafw00f`/`WhatWaf`
- **P1 à ajouter** : `Subfinder`, `Naabu`, `Wappalyzer`, `dalfox`, `SQLmap`, `gau` (non listé mais complémentaire)
- **P2** : `testssl.sh`/`SSLyze` pour TLS, `GitTools` pour .git, `pagodo` pour dorking passif
- Chaque outil → `PHASE3/plugins/<outil>.yaml` + parser `→ Finding.location.url` + `Oracle http_response` N/N + `ScopeEnforcer` RDN

> Total web : **119 outils** — catalogue complet prêt pour génération plugins.
