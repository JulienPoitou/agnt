import { REJEU } from "../data/rejeu";

export default function Landing() {
  return (
    <div className="land">
      <div className="hero">
        <div className="kicker">moteur d'analyse de sécurité · déterministe</div>
        <h1>
          L'analyse de sécurité, <s>sans zone grise</s>
        </h1>
        <p className="sub">
          AGNT exécute des outils passifs (checkov, trivy, semgrep, gitleaks) dans un sandbox
          réseau coupé, sous policy OPA. Chaque observation est tracée, chaque regroupement
          justifié, aucune gravité inventée. Le rapport est écrit sans LLM — deux exécutions sur
          la même cible donnent le même résultat.
        </p>
        <a className="cta" href="#/console">
          ouvrir la console →
        </a>
        <a className="cta ghost" href="#/console">
          voir un rejeu réel
        </a>
      </div>

      <div className="stats">
        <div className="stat">
          <div className="v">38</div>
          <div className="l">observations · rejeu checkov 3.3.15</div>
        </div>
        <div className="stat">
          <div className="v">{REJEU.clusters.length}</div>
          <div className="l">regroupements justifiés</div>
        </div>
        <div className="stat">
          <div className="v">0</div>
          <div className="l">gravité inventée</div>
        </div>
        <div className="stat">
          <div className="v">100%</div>
          <div className="l">exécutions hors ligne</div>
        </div>
      </div>

      <div className="arch">
        <div className="pre">
          intent → plan typé → <span className="ar">opa:allow</span> → sandbox(bwrap) → tool →
          norm → corr → rapport
        </div>
      </div>

      <div className="sect">
        <h2>
          Ce que fait le moteur, <s>pas à pas</s>
        </h2>
        <div className="cards">
          <div className="card">
            <span className="tag">sandbox</span>
            <h3>Exécution cloisonnée</h3>
            <p>
              bwrap, uid 1000, racine lecture seule, réseau coupé. Les outils passifs ne sortent
              jamais du périmètre de la cible.
            </p>
          </div>
          <div className="card">
            <span className="tag">policy</span>
            <h3>Garde-fous OPA</h3>
            <p>
              Chaque exécution passe une policy ALLOW/DENY : profil de cible, classe de risque de
              l'outil, réseau. Les refus sont tracés, jamais silencieux.
            </p>
          </div>
          <div className="card">
            <span className="tag">corr</span>
            <h3>Corrélation justifiée</h3>
            <p>
              Les observations sont regroupées par motifs explicites (même fichier, même ligne,
              même cadre). Chaque cluster affiche ses preuves.
            </p>
          </div>
          <div className="card">
            <span className="tag">honnêteté</span>
            <h3>Rien d'inventé</h3>
            <p>
              Gravité UNKNOWN conservée si aucune source ne la fournit. Capacité « non
              applicable » plutôt que résultat déguisé. La maquette se déclare comme maquette.
            </p>
          </div>
        </div>
      </div>

      <div className="sect">
        <h2>
          Le rejeu disponible <s>maintenant</s>
        </h2>
        <div className="cards">
          <div className="card">
            <span className="tag">IAC_SCAN</span>
            <h3>{REJEU.cible}</h3>
            <p>
              Terraform 15 · Kubernetes 20 · Dockerfile 3 — capture versionnée du run réel
              (mission archivée {REJEU.mission.split("/").pop()}).
            </p>
          </div>
          <div className="card">
            <span className="tag">couverture</span>
            <h3>4 capacités déclarées</h3>
            <p>
              1 exécutée (checkov), 3 « non applicables » assumées — trivy, semgrep, gitleaks
              n'avaient rien à analyser sur cette cible.
            </p>
          </div>
        </div>
        <a className="cta" href="#/console">
          ouvrir la console →
        </a>
      </div>

      <div className="foot">
        <span>agnt::console — rejeu honnête, ou moteur réel via ./lancer.sh</span>
        <span>source : capture versionnée du dépôt · API PHASE3/interface/api.py</span>
      </div>
    </div>
  );
}
