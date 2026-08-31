import { useEffect, useMemo, useRef, useState } from "react";
import { REJEU, type Observation, type Cluster, type Couverture } from "../data/rejeu";

const TABS = ["journal", "observations", "clusters", "couverture", "réglages"] as const;
type Tab = (typeof TABS)[number];

const TAB_LABEL: Record<Tab, string> = {
  journal: "JOURNAL",
  observations: "OBSERVATIONS",
  clusters: "CLUSTERS",
  couverture: "COUVERTURE",
  réglages: "RÉGLAGES",
};

function JournalView() {
  const [visible, setVisible] = useState(0);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    if (visible >= REJEU.journal.length) return;
    timer.current = window.setTimeout(() => setVisible((v) => v + 1), 260);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [visible]);

  const lines = REJEU.journal.slice(0, visible);
  const done = visible >= REJEU.journal.length;

  return (
    <div className="view">
      {lines.map((l, i) => (
        <div className="ln" key={i}>
          <span className="n">{String(i + 1).padStart(2, "0")}</span>
          <span className={`tg tg-${l.tag}`}>{l.tag}</span>
          <span className="m">
            {l.msg}
            {l.detail && <span className="d"> — {l.detail}</span>}
          </span>
        </div>
      ))}
      {!done && <div className="ln"><span className="n">…</span><span className="tg tg-sys">sys</span><span className="m">rejeu en cours…</span></div>}
      {done && (
        <div className="proof">
          <b>preuve de déterminisme</b> — deux exécutions du moteur sur la même cible ont produit
          le même rapport (38 observations · {REJEU.clusters.length} regroupements · 0 invention de
          gravité). Capture source :{" "}
          <code>PHASE3/testrepo_iac/artefacts_captures/checkov_multiframework.json</code>.
        </div>
      )}
    </div>
  );
}

function ObservationsView() {
  const [filtre, setFiltre] = useState("");
  const obs: Observation[] = useMemo(() => {
    const q = filtre.trim().toLowerCase();
    if (!q) return REJEU.observations;
    return REJEU.observations.filter(
      (o) =>
        o.regle.toLowerCase().includes(q) ||
        o.message.toLowerCase().includes(q) ||
        o.fichier.toLowerCase().includes(q) ||
        o.cadre.toLowerCase().includes(q),
    );
  }, [filtre]);

  return (
    <div className="view">
      <div className="cmd" style={{ padding: "0 0 12px", borderBottom: 0 }}>
        <div className="in" style={{ marginTop: 0 }}>
          <span className="ch">$</span>
          <input
            placeholder="filtrer (règle, message, fichier, cadre)…"
            value={filtre}
            onChange={(e) => setFiltre(e.target.value)}
          />
        </div>
        <div className="hint">
          {obs.length} / {REJEU.observations.length} observations affichées
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>id</th>
            <th>règle</th>
            <th>message</th>
            <th>fichier:ligne</th>
            <th>gravité</th>
            <th>cadre</th>
          </tr>
        </thead>
        <tbody>
          {obs.map((o) => (
            <tr key={o.id}>
              <td style={{ color: "var(--dim)" }}>{o.id}</td>
              <td style={{ color: "var(--acc)" }}>{o.regle}</td>
              <td>{o.message}</td>
              <td>
                {o.fichier}
                {o.ligne !== null ? `:${o.ligne}` : ""}
              </td>
              <td className={`sev sev-${o.gravite}`}>{o.gravite}</td>
              <td style={{ color: "var(--dim)" }}>{o.cadre}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ClustersView() {
  return (
    <div className="view">
      <table>
        <thead>
          <tr>
            <th>cluster</th>
            <th>membres</th>
            <th>motifs</th>
            <th>fichier</th>
            <th>gravité</th>
          </tr>
        </thead>
        <tbody>
          {REJEU.clusters.map((c: Cluster) => (
            <tr key={c.id}>
              <td style={{ color: "var(--acc)" }}>{c.id}</td>
              <td style={{ color: "var(--dim)" }}>{c.membres.length} obs.</td>
              <td>{c.motifs.join(" · ")}</td>
              <td>{c.fichier}</td>
              <td className={`sev sev-${c.gravite}`}>{c.gravite}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="note">
        <b>règle de corrélation</b> — un cluster regroupe les observations qui pointent la même
        localisation (fichier + ligne). Les motifs kubernetes sont fusionnés par cadre. La gravité
        reste <b>UNKNOWN</b> tant qu'aucune source ne la fournit : elle n'est jamais inventée.
      </div>
    </div>
  );
}

function CouvertureView() {
  return (
    <div className="view">
      <table>
        <thead>
          <tr>
            <th>capacité</th>
            <th>provider</th>
            <th>risque</th>
            <th>statut</th>
            <th>détail</th>
          </tr>
        </thead>
        <tbody>
          {REJEU.couverture.map((c: Couverture) => (
            <tr key={c.capacite}>
              <td className="capn">{c.capacite}</td>
              <td>{c.provider}</td>
              <td>
                <span className={`rk rk-${c.risque}`}>{c.risque}</span>
              </td>
              <td>{c.statut}</td>
              <td className="capp">{c.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReglagesView() {
  return (
    <div className="view">
      <div className="set">
        <span className="k">moteur</span>
        <select disabled value="local">
          <option value="local">moteur local (non connecté)</option>
        </select>
        <span className="locked">verrouillé — aucune API moteur détectée</span>
      </div>
      <div className="set">
        <span className="k">source de données</span>
        <select disabled value="rejeu">
          <option value="rejeu">rejeu d'exécution passée (capture checkov)</option>
        </select>
      </div>
      <div className="set">
        <span className="k">cible du rejeu</span>
        <select disabled value="testrepo_iac">
          <option value="testrepo_iac">{REJEU.cible}</option>
        </select>
      </div>
      <div className="note">
        <b>contrat honnête</b> — cette console n'exécute rien. Elle rejoue une exécution passée,
        versionnée dans le dépôt. Le passage au moteur réel se fera par une API unique
        (<code>POST /missions</code>) sans changer l'écran.
      </div>
    </div>
  );
}

export default function Console() {
  const [tab, setTab] = useState<Tab>("journal");
  const [cmd, setCmd] = useState("");
  const [sent, setSent] = useState<string | null>(null);

  const submit = () => {
    if (!cmd.trim()) return;
    setSent(cmd.trim());
    setCmd("");
  };

  return (
    <div className="frame">
      <div className="hd">
        <div className="b">
          agnt<s>::</s>console
        </div>
        <div className="st">
          profil <b>controlled</b> · réseau <b>coupé</b> · moteur <b>hors ligne</b>
        </div>
      </div>

      <div className="banner">
        <b>MAQUETTE</b> — rejeu d'une exécution passée · aucune commande n'est exécutée ·
        source : capture versionnée du moteur
      </div>

      <div className="cmd">
        <div className="lbl">commande</div>
        <div className="in">
          <span className="ch">$</span>
          <input
            placeholder="analyse la sécurité de ce dépôt…"
            value={cmd}
            onChange={(e) => setCmd(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
          />
          <button onClick={submit}>exécuter</button>
        </div>
        <div className="hint">
          {sent ? (
            <>
              <span style={{ color: "var(--warn)" }}>
                « {sent} » — mise en file simulée (maquette, moteur hors ligne)
              </span>
            </>
          ) : (
            <>
              maquette : la commande n'est pas transmise.{" "}
              <kbd>Entrée</kbd> pour voir la réponse simulée.
            </>
          )}
        </div>
      </div>

      <div className="tabs">
        {TABS.map((t) => (
          <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>
            {TAB_LABEL[t]}
          </button>
        ))}
      </div>

      {tab === "journal" && <JournalView />}
      {tab === "observations" && <ObservationsView />}
      {tab === "clusters" && <ClustersView />}
      {tab === "couverture" && <CouvertureView />}
      {tab === "réglages" && <ReglagesView />}

      <div className="nav">
        <a href="#/">accueil</a>
        {TABS.map((t) => (
          <a
            key={t}
            className={tab === t ? "here" : ""}
            onClick={(e) => {
              e.preventDefault();
              setTab(t);
            }}
          >
            {TAB_LABEL[t].toLowerCase()}
          </a>
        ))}
      </div>
    </div>
  );
}
