"use client";

import { useState } from "react";

import type { HistoryList, MissionDetail } from "@/lib/api";

const labels: Record<string, string> = {
  termine: "Terminé",
  refuse: "Refusé",
  erreur: "Erreur",
  inconnu: "Inconnu",
  en_file: "En file",
  en_cours: "En cours",
};

export function MissionWorkspace({
  history,
  detail,
}: Readonly<{ history: HistoryList; detail: MissionDetail }>) {
  const [selected, setSelected] = useState(detail.mission.mission_id);
  const current = history.items.find((x) => x.mission_id === selected) ?? detail.mission;
  const findings = current.findings_summary;
  return (
    <div className="agnt-shell">
      <aside className="mission-index">
        <div className="brand">
          AGNT <small>DESIGN LAB</small>
        </div>
        <div className="eyebrow">MISSIONS · {history.items.length}</div>
        {history.items.map((m) => (
          <button
            className={m.mission_id === selected ? "mission active" : "mission"}
            key={m.mission_id}
            onClick={() => setSelected(m.mission_id)}
          >
            <b>{m.request.title}</b>
            <span>{m.target.display_name}</span>
            <em className={"status " + m.status}>{labels[m.status] ?? m.status}</em>
          </button>
        ))}
      </aside>
      <main className="case">
        <header className="case-head">
          <div>
            <div className="eyebrow">MISSION / {current.mission_id}</div>
            <h1>{current.request.title}</h1>
            <p>
              {current.target.type} · {current.target.display_name} · run {current.run_id ?? "aucun run_id publié"}
            </p>
          </div>
          <span className={"status large " + current.status}>{labels[current.status] ?? current.status}</span>
        </header>
        <section className="coverage">
          <div>
            <label>PROVIDERS</label>
            <strong>{detail.data.executions.length}</strong>
          </div>
          <div>
            <label>FINDINGS</label>
            <strong>{findings ? findings.total : "inconnu (non consigné)"}</strong>
          </div>
          <div>
            <label>CORRÉLATIONS</label>
            <strong>{current.clusters_count ?? "inconnu (non consigné)"}</strong>
          </div>
          <div>
            <label>TIMELINE</label>
            <strong>
              {detail.data.timeline.returned_events}/{detail.data.timeline.total_events}
            </strong>
          </div>
        </section>
        <section className="content-grid">
          <div>
            <div className="section-title">
              <h2>Executions</h2>
              <span>agnt.execution-status.v1</span>
            </div>
            <div className="execution-list">
              {detail.data.executions.map((x) => (
                <div key={x.provider_id}>
                  <strong>{x.display_name}</strong>
                  <span className={"status " + x.execution.value}>execution : {x.execution.value}</span>
                  <small>detection : {x.detection.value}</small>
                </div>
              ))}
            </div>
          </div>
          <aside className="report">
            <div className="eyebrow">TIMELINE · agnt.timeline.v1</div>
            <p>
              {detail.data.timeline.state} · legacy events : {detail.data.events.length} (compteurs indépendants,
              jamais fusionnés)
            </p>
            {detail.data.timeline.events.map((e) => (
              <div className="event" key={e.event_id}>
                <span>{e.kind}</span>
                <small>
                  seq {e.position} · {e.safe_summary}
                </small>
              </div>
            ))}
          </aside>
        </section>
      </main>
    </div>
  );
}
