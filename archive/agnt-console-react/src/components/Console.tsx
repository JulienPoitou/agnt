import { useEffect, useMemo, useRef, useState } from "react";
import { REJEU, type Observation, type Cluster, type Couverture } from "../data/rejeu";
import { api, type CibleApi, type RunEtat } from "../api";
import { normaliser, type LiveData, type JournalLigne } from "../normaliser";

const TABS = ["journal", "observations", "clusters", "couverture", "réglages"] as const;
type Tab = (typeof TABS)[number];

const TAB_LABEL: Record<Tab, string> = {
  journal: "JOURNAL",
  observations: "OBSERVATIONS",
  clusters: "CLUSTERS",
  couverture: "COUVERTURE",
  réglages: "RÉGLAGES",
};

type Mode = "live" | "replay";
type RunStatut = RunEtat["statut"] | "idle";

/** Modèle de vues unifié : rejeu (capture) ou live (mission réelle normalisée). */
interface Vue {
  observations: Observation[];
  clusters: Cluster[];
  couverture: Couverture[];
  journal: JournalLigne[];
  cible: string;
}

function JournalView({ lignes, vivant }: { lignes: JournalLigne[]; vivant: boolean }) {
  const [visible, setVisible] = useState(vivant ? lignes.length : 0);
  const timer = useRef<number | null>(null);

  // En rejeu on révèle les lignes en cascade ; en live on montre tout (le
  // moteur, pas l'écran, décide du rythme).
  useEffect(() => {
    if (vivant) {
      setVisible(lignes.length);
      return;
    }
    setVisible(0);
  }, [vivant, lignes.length]);

  useEffect(() => {
    if (vivant) return;
    if (visible >= lignes.length) return;
    timer.current = window.setTimeout(() => setVisible((v) => v + 1), 260);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [visible, vivant, lignes.length]);

  const lines = lignes.slice(0, visible);
  const done = visible >= lignes.length;

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
      {done && !vivant && (
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

function ObservationsView({ obs }: { obs: Observation[] }) {
  const [filtre, setFiltre] = useState("");
  const vues: Observation[] = useMemo(() => {
    const q = filtre.trim().toLowerCase();
    if (!q) return obs;
    return obs.filter(
      (o) =>
        o.regle.toLowerCase().includes(q) ||
        o.message.toLowerCase().includes(q) ||
        o.fichier.toLowerCase().includes(q) ||
        o.cadre.toLowerCase().includes(q),
    );
  }, [filtre, obs]);

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
          {vues.length} / {obs.length} observations affichées
        </div>
      </div>
      {obs.length === 0 ? (
        <div className="note">
          <b>aucune observation</b> — l'archive ne porte aucun finding (0 constat, ou mission
          refusée / non applicable). Ce n'est pas une erreur d'affichage.
        </div>
      ) : (
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
            {vues.map((o) => (
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
      )}
    </div>
  );
}

function ClustersView({ clusters }: { clusters: Cluster[] }) {
  return (
    <div className="view">
      {clusters.length === 0 ? (
        <div className="note"><b>aucun regroupement</b> — rien à corréler sur cette mission.</div>
      ) : (
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
            {clusters.map((c: Cluster) => (
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
      )}
      <div className="note">
        <b>règle de corrélation</b> — un cluster regroupe les observations qui pointent la même
        localisation (fichier + ligne). La gravité reste <b>UNKNOWN</b> tant qu'aucune source ne la
        fournit : elle n'est jamais inventée.
      </div>
    </div>
  );
}

function CouvertureView({ couverture }: { couverture: Couverture[] }) {
  return (
    <div className="view">
      {couverture.length === 0 ? (
        <div className="note"><b>couverture vide</b> — aucun outil n'a été mené sur cette mission.</div>
      ) : (
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
            {couverture.map((c: Couverture, i) => (
              <tr key={`${c.capacite}-${i}`}>
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
      )}
    </div>
  );
}

function ReglagesView({ mode, moteur, setMoteur }: {
  mode: Mode;
  moteur: string;
  setMoteur: (m: string) => void;
}) {
  return (
    <div className="view">
      <div className="set">
        <span className="k">moteur</span>
        <select disabled={mode !== "live"} value={moteur} onChange={(e) => setMoteur(e.target.value)}>
          <option value="auto">auto (le moteur choisit)</option>
          <option value="deterministe">déterministe (sans LLM)</option>
          <option value="llm">llm</option>
        </select>
        <span className="locked">
          {mode === "live" ? "API moteur détectée — choix transmis au lancement" : "verrouillé — aucune API moteur détectée"}
        </span>
      </div>
      <div className="set">
        <span className="k">source de données</span>
        <select disabled value={mode === "live" ? "live" : "rejeu"}>
          {mode === "live" ? (
            <option value="live">API moteur réelle (PHASE3/interface/api.py)</option>
          ) : (
            <option value="rejeu">rejeu d'exécution passée (capture checkov)</option>
          )}
        </select>
      </div>
      <div className="note">
        {mode === "live" ? (
          <>
            <b>moteur connecté</b> — les RUN lancent <code>analyser.lancer()</code> pour de vrai.
            Sans outils installés sur la machine, un run aboutit à un <b>refus nommé</b> (ex.
            « binaire OPA introuvable »), pas à un spinner éternel.
          </>
        ) : (
          <>
            <b>contrat honnête</b> — l'API moteur ne répond pas : cette console rejoue une
            exécution passée, versionnée dans le dépôt. Démarrez l'API (
            <code>./lancer.sh</code>) pour passer au moteur réel.
          </>
        )}
      </div>
    </div>
  );
}

export default function Console() {
  const [tab, setTab] = useState<Tab>("journal");
  const [cmd, setCmd] = useState("analyse la sécurité de ce dépôt");
  const [mode, setMode] = useState<Mode>("replay");
  const [moteur, setMoteur] = useState("auto");
  const [cibles, setCibles] = useState<CibleApi[]>([]);
  const [cible, setCible] = useState<string>("");
  const [runId, setRunId] = useState<string | null>(null);
  const [statut, setStatut] = useState<RunStatut>("idle");
  const [live, setLive] = useState<LiveData | null>(null);
  const [motif, setMotif] = useState<string | null>(null);

  // Détection de l'API au montage + chargement des cibles si présente.
  useEffect(() => {
    let actif = true;
    api
      .vivante()
      .then(async () => {
        if (!actif) return;
        setMode("live");
        try {
          const cs = await api.cibles();
          if (!actif) return;
          setCibles(cs);
          if (cs.length) setCible(cs[0].chemin);
        } catch {
          /* cibles optionnelles */
        }
      })
      .catch(() => actif && setMode("replay"));
    return () => {
      actif = false;
    };
  }, []);

  // Polling d'un run tant qu'il n'est pas terminal.
  useEffect(() => {
    if (!runId || mode !== "live") return;
    let stop = false;
    const tick = async () => {
      try {
        const e = await api.etat(runId);
        if (stop) return;
        setStatut(e.statut);
        if (e.statut === "termine" && e.donnees) {
          setLive(normaliser(e));
          setMotif(null);
        } else if (e.statut === "refuse" || e.statut === "erreur") {
          setLive(e.donnees ? normaliser(e) : null);
          setMotif(e.resume?.motif || e.erreur || "refusé par la politique (fail-closed)");
        }
      } catch {
        /* on réessaie au prochain tick */
      }
    };
    tick();
    const h = window.setInterval(() => {
      if (stop) return;
      tick();
    }, 1200);
    return () => {
      stop = true;
      window.clearInterval(h);
    };
  }, [runId, mode]);

  const occupe = statut === "en_file" || statut === "en_cours";

  const submit = async () => {
    if (!cmd.trim() || mode !== "live") {
      // En mode rejeu, on simule la mise en file (maquette).
      if (cmd.trim()) setTab("journal");
      return;
    }
    if (!cible) return;
    setStatut("en_file");
    setLive(null);
    setMotif(null);
    setTab("journal");
    try {
      const r = await api.lancer(cmd.trim(), cible, { moteur });
      setRunId(r.id);
    } catch (e) {
      setStatut("erreur");
      setMotif(e instanceof Error ? e.message : "lancement impossible");
    }
  };

  const vue: Vue = live
    ? {
        observations: live.observations,
        clusters: live.clusters,
        couverture: live.couverture,
        journal: live.journal,
        cible: live.cible,
      }
    : {
        observations: REJEU.observations,
        clusters: REJEU.clusters,
        couverture: REJEU.couverture,
        journal: REJEU.journal,
        cible: REJEU.cible,
      };

  return (
    <div className="frame">
      <div className="hd">
        <div className="b">
          agnt<s>::</s>console
        </div>
        <div className="st">
          {mode === "live" ? (
            <>
              profil <b>controlled</b> · réseau <b>coupé</b> · moteur{" "}
              <b style={{ color: "var(--ok, #4ade80)" }}>connecté</b>
            </>
          ) : (
            <>
              profil <b>controlled</b> · réseau <b>coupé</b> · moteur <b>hors ligne</b>
            </>
          )}
        </div>
      </div>

      {mode === "live" ? (
        <div className="banner" style={{ borderColor: "var(--ok, #4ade80)" }}>
          <b>MOTEUR CONNECTÉ</b> — exécution réelle via <code>analyser.lancer()</code> · un run à la
          fois · les refus sont nommés, jamais masqués
        </div>
      ) : (
        <div className="banner">
          <b>MAQUETTE</b> — rejeu d'une exécution passée · aucune commande n'est exécutée ·
          source : capture versionnée du moteur
        </div>
      )}

      <div className="cmd">
        <div className="lbl">commande</div>
        {mode === "live" && (
          <div className="in" style={{ marginBottom: 8 }}>
            <span className="ch">@</span>
            <select
              style={{ flex: 1, background: "transparent", border: 0, color: "inherit", font: "inherit" }}
              value={cible}
              onChange={(e) => setCible(e.target.value)}
              disabled={occupe}
            >
              {cibles.map((c) => (
                <option key={c.chemin} value={c.chemin} style={{ color: "#000" }}>
                  {c.nom} — {c.chemin} ({c.langages.join(", ") || "?"})
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="in">
          <span className="ch">$</span>
          <input
            placeholder="analyse la sécurité de ce dépôt…"
            value={cmd}
            onChange={(e) => setCmd(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            disabled={occupe}
          />
          <button onClick={submit} disabled={occupe || (mode === "live" && !cible)}>
            {occupe ? "en cours…" : "exécuter"}
          </button>
        </div>
        <div className="hint">
          {occupe ? (
            <span style={{ color: "var(--warn)" }}>
              run {runId} · {statut === "en_file" ? "en file" : "en cours d'exécution"}…
            </span>
          ) : statut === "refuse" && motif ? (
            <span style={{ color: "var(--warn)" }}>
              <b>refus nommé</b> — {motif}
            </span>
          ) : statut === "erreur" ? (
            <span style={{ color: "var(--warn)" }}>erreur — {motif}</span>
          ) : mode === "replay" ? (
            <>
              maquette : la commande n'est pas transmise. <kbd>Entrée</kbd> pour voir la réponse
              simulée.
            </>
          ) : live ? (
            <>mission {live.mission} · {live.observations.length} observation(s) · prête pour un nouveau run.</>
          ) : (
            <>moteur prêt — choisissez une cible puis <kbd>Entrée</kbd>.</>
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

      {tab === "journal" && <JournalView lignes={vue.journal} vivant={mode === "live" && !!live} />}
      {tab === "observations" && <ObservationsView obs={vue.observations} />}
      {tab === "clusters" && <ClustersView clusters={vue.clusters} />}
      {tab === "couverture" && <CouvertureView couverture={vue.couverture} />}
      {tab === "réglages" && <ReglagesView mode={mode} moteur={moteur} setMoteur={setMoteur} />}

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
