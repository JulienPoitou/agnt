import { useEffect, useRef, useState } from "react";
import { REJEU } from "../data/rejeu";

/** Fond animé : aurora + grille + bruit. Purement décoratif (aria-hidden). */
function Backdrop() {
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="blob blob-a" />
      <div className="blob blob-b" />
      <div className="blob blob-c" />
      <div className="grid-fx" />
      <div className="noise" />
      <div className="vignette" />
    </div>
  );
}

/** Révèle son contenu au premier passage dans le viewport. */
function useInView<T extends HTMLElement>(threshold = 0.12) {
  const ref = useRef<T | null>(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) {
        setInView(true);
        io.disconnect();
      }
    }, { threshold });
    io.observe(el);
    return () => io.disconnect();
  }, [threshold]);
  return { ref, inView };
}

function Reveal({
  children,
  delay = 0,
  className = "",
}: {
  children: React.ReactNode;
  delay?: number;
  className?: string;
}) {
  const { ref, inView } = useInView<HTMLDivElement>();
  return (
    <div
      ref={ref}
      className={`rv ${inView ? "in" : ""} ${className}`.trim()}
      style={{ "--d": `${delay}ms` } as React.CSSProperties}
    >
      {children}
    </div>
  );
}

/** Compteur animé (ease-out cubique), lancé quand `started` passe à vrai. */
function CountUp({
  to,
  started,
  decimals = 0,
  suffix = "",
}: {
  to: number;
  started: boolean;
  decimals?: number;
  suffix?: string;
}) {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (!started) return;
    let raf = 0;
    const t0 = performance.now();
    const dur = 1500;
    const ease = (p: number) => 1 - Math.pow(1 - p, 3);
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / dur);
      setV(to * ease(p));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [started, to]);
  return (
    <>
      {v.toFixed(decimals)}
      {suffix}
    </>
  );
}

function Stat({
  to,
  suffix = "",
  decimals = 0,
  label,
  delay = 0,
}: {
  to: number;
  suffix?: string;
  decimals?: number;
  label: string;
  delay?: number;
}) {
  const { ref, inView } = useInView<HTMLDivElement>();
  return (
    <div
      ref={ref}
      className={`stat rv ${inView ? "in" : ""}`.trim()}
      style={{ "--d": `${delay}ms` } as React.CSSProperties}
    >
      <div className="v">
        <CountUp to={to} started={inView} decimals={decimals} suffix={suffix} />
      </div>
      <div className="l">{label}</div>
    </div>
  );
}

const PIPELINE = [
  { num: "01", lbl: "intent" },
  { num: "02", lbl: "plan typé" },
  { num: "03", lbl: "opa:allow" },
  { num: "04", lbl: "sandbox" },
  { num: "05", lbl: "tool" },
  { num: "06", lbl: "norm" },
  { num: "07", lbl: "corr" },
  { num: "08", lbl: "rapport" },
];

const OUTILS = [
  "checkov",
  "trivy",
  "semgrep",
  "gitleaks",
  "bandit",
  "kics",
  "grype",
  "hadolint",
  "shellcheck",
  "opa",
  "bwrap",
];

export default function Landing() {
  const [mx, setMx] = useState<string | null>(null);
  const [my, setMy] = useState<string | null>(null);

  return (
    <div className="land">
      <Backdrop />

      <header className="kbar">
        <div className="brand">
          agnt<s>::</s>console
        </div>
        <div className="k-side">
          <span className="chip">
            <i /> réseau coupé
          </span>
          <a className="btn mini" href="#/console">
            ouvrir la console →
          </a>
        </div>
      </header>

      <section
        className="hero"
        onMouseMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          setMx(`${e.clientX - r.left}px`);
          setMy(`${e.clientY - r.top}px`);
        }}
      >
        <div
          className="spot"
          aria-hidden="true"
          style={
            mx && my
              ? ({ "--mx": mx, "--my": my } as React.CSSProperties)
              : undefined
          }
        />
        <div className="kicker">moteur d'analyse de sécurité · déterministe</div>
        <h1>
          <span className="l1">L'analyse de sécurité,</span>
          <br />
          <span className="hl">sans zone grise.</span>
        </h1>
        <p className="sub">
          AGNT exécute des outils passifs (<b>checkov</b>, <b>trivy</b>, <b>semgrep</b>,{" "}
          <b>gitleaks</b>) dans un sandbox réseau coupé, sous policy OPA. Chaque observation est
          tracée, chaque regroupement justifié, aucune gravité inventée. Le rapport est écrit sans
          LLM — deux exécutions sur la même cible donnent le même résultat.
        </p>
        <div className="ctas">
          <a className="btn" href="#/console">
            ouvrir la console <span className="arr">→</span>
          </a>
          <a className="btn ghost" href="#/console">
            voir un rejeu réel
          </a>
        </div>
        <div className="hero-meta">
          <span className="chip">
            <span className="ac">sandbox</span> bwrap · --unshare-net
          </span>
          <span className="chip">
            <span className="ac">policy</span> OPA ALLOW/DENY
          </span>
          <span className="chip">
            <span className="ac">8</span> outils passifs qualifiés
          </span>
          <span className="chip">
            <span className="ac">rapport</span> sans LLM
          </span>
        </div>
      </section>

      <div className="pip-wrap">
        <div className="pip" aria-hidden="true">
          <div className="pip-line">
            <div className="pip-comet" />
          </div>
          <div className="pip-nodes">
            {PIPELINE.map((s) => (
              <div className="pip-node" key={s.num}>
                <div className="n-top">
                  <span className="n-num">{s.num}</span>
                  <span className="n-dot" />
                </div>
                <span className="n-lbl">{s.lbl}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="stats">
        <Stat to={REJEU.observations.length} label="observations · rejeu checkov 3.3.15" />
        <Stat to={REJEU.clusters.length} label="regroupements justifiés" delay={90} />
        <Stat to={0} label="gravité inventée" delay={180} />
        <Stat to={100} suffix="%" label="exécutions hors ligne" delay={270} />
      </div>

      <div className="marquee" aria-hidden="true">
        <div className="track">
          {[...OUTILS, ...OUTILS].map((o, i) => (
            <span className="m-item" key={`${o}-${i}`}>
              <b>{o}</b>
              <span className="sep">◆</span>
            </span>
          ))}
        </div>
      </div>

      <section className="sect">
        <Reveal>
          <h2>
            Ce que fait le moteur, <s>pas à pas</s>
          </h2>
          <p className="lead">
            Huit étages tracés, du brainstorming à la page : chaque refus est nommé, chaque repli
            est consigné.
          </p>
        </Reveal>
        <div className="cards">
          <Reveal delay={0}>
            <div className="card">
              <span className="tag">sandbox</span>
              <h3>Exécution cloisonnée</h3>
              <p>
                bwrap, uid 1000, racine lecture seule, réseau coupé. Les outils passifs ne sortent
                jamais du périmètre de la cible.
              </p>
            </div>
          </Reveal>
          <Reveal delay={90}>
            <div className="card">
              <span className="tag">policy</span>
              <h3>Garde-fous OPA</h3>
              <p>
                Chaque exécution passe une policy ALLOW/DENY : profil de cible, classe de risque de
                l'outil, réseau. Les refus sont tracés, jamais silencieux.
              </p>
            </div>
          </Reveal>
          <Reveal delay={180}>
            <div className="card">
              <span className="tag">corr</span>
              <h3>Corrélation justifiée</h3>
              <p>
                Les observations sont regroupées par motifs explicites (même fichier, même ligne,
                même cadre). Chaque cluster affiche ses preuves.
              </p>
            </div>
          </Reveal>
          <Reveal delay={270}>
            <div className="card">
              <span className="tag">honnêteté</span>
              <h3>Rien d'inventé</h3>
              <p>
                Gravité UNKNOWN conservée si aucune source ne la fournit. Capacité « non
                applicable » plutôt que résultat déguisé. La maquette se déclare comme maquette.
              </p>
            </div>
          </Reveal>
        </div>
      </section>

      <section className="sect">
        <Reveal>
          <h2>
            Le rejeu disponible <s>maintenant</s>
          </h2>
          <p className="lead">
            Capture versionnée d'un run réel — consultable sans aucun outil installé.
          </p>
        </Reveal>
        <div className="cards">
          <Reveal delay={0}>
            <div className="card">
              <span className="tag">IAC_SCAN</span>
              <h3>{REJEU.cible}</h3>
              <p>
                Terraform 15 · Kubernetes 20 · Dockerfile 3 — capture versionnée du run réel
                (mission archivée {REJEU.mission.split("/").pop()}).
              </p>
            </div>
          </Reveal>
          <Reveal delay={100}>
            <div className="card">
              <span className="tag">couverture</span>
              <h3>4 capacités déclarées</h3>
              <p>
                1 exécutée (checkov), 3 « non applicables » assumées — trivy, semgrep, gitleaks
                n'avaient rien à analyser sur cette cible.
              </p>
            </div>
          </Reveal>
        </div>
        <Reveal className="sect-foot">
          <a className="btn" href="#/console">
            ouvrir la console <span className="arr">→</span>
          </a>
        </Reveal>
      </section>

      <footer className="foot">
        <span>
          agnt::console — <b>rejeu honnête</b>, ou moteur réel via ./lancer.sh
        </span>
        <span className="ff">
          source : capture versionnée du dépôt · API PHASE3/interface/api.py
        </span>
      </footer>
    </div>
  );
}
