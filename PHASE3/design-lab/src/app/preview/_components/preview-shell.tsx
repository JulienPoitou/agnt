"use client";

import Link from "next/link";
import { useState } from "react";

export type PreviewVariant = "linear" | "forensics" | "minimal";

const variants: { id: PreviewVariant; label: string; description: string }[] = [
  { id: "linear", label: "Linear", description: "Workspace calme et rapide" },
  { id: "forensics", label: "Forensics", description: "Poste d'investigation dense" },
  { id: "minimal", label: "Minimal", description: "Vue claire et essentielle" },
];

const missions = [
  { id: "M-1042", title: "Audit production API", target: "github.com/acme/api", status: "Completed", findings: 12, time: "2 min ago" },
  { id: "M-1041", title: "Dependency review", target: "github.com/acme/web", status: "Running", findings: 4, time: "18 min ago" },
  { id: "M-1040", title: "Secret exposure scan", target: "github.com/acme/infra", status: "Needs review", findings: 7, time: "Yesterday" },
  { id: "M-1039", title: "Pull request #842", target: "acme/platform", status: "Completed", findings: 0, time: "Yesterday" },
  { id: "M-1038", title: "Container baseline", target: "registry.acme.io/worker", status: "Failed", findings: 2, time: "Mon" },
];

const statusClass = (status: string) => status.toLowerCase().replace(" ", "-");

export function PreviewShell({ variant }: Readonly<{ variant: PreviewVariant }>) {
  const [selected, setSelected] = useState(0);
  const [query, setQuery] = useState("");
  const visibleMissions = missions.filter((mission) =>
    `${mission.title} ${mission.target}`.toLowerCase().includes(query.toLowerCase()),
  );
  const activeMission = missions[selected] ?? missions[0];

  return (
    <main className={`preview-app preview-${variant}`}>
      <aside className="preview-sidebar">
        <Link href="/preview/linear" className="preview-logo"><span className="logo-mark">A</span><span>AGNT</span></Link>
        <div className="workspace-switcher"><span className="workspace-dot" /> Acme Security <span className="chevron">⌄</span></div>
        <nav className="preview-nav" aria-label="Preview navigation">
          <button className="nav-item active"><span>⌘</span> Overview <kbd>G O</kbd></button>
          <button className="nav-item"><span>◌</span> Missions <b>24</b></button>
          <button className="nav-item"><span>△</span> Findings <b className="alert-count">19</b></button>
          <button className="nav-item"><span>⌁</span> Targets</button>
          <div className="nav-label">Workspace</div>
          <button className="nav-item"><span>◫</span> Providers</button>
          <button className="nav-item"><span>◈</span> Evidence</button>
          <button className="nav-item"><span>⚙</span> Settings</button>
        </nav>
        <div className="sidebar-bottom"><div className="system-state"><span className="pulse" /> All systems operational</div><div className="user-chip"><span className="avatar">JD</span><span><strong>Jean Dupont</strong><small>Administrator</small></span><span>•••</span></div></div>
      </aside>

      <section className="preview-content">
        <header className="preview-header">
          <div className="breadcrumbs"><span>Overview</span><span>/</span><strong>{variant === "forensics" ? "Investigation room" : variant === "minimal" ? "Missions" : "Security workspace"}</strong></div>
          <div className="header-actions"><label className="search-box"><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search anything..." /><kbd>⌘ K</kbd></label><button className="icon-button" aria-label="Notifications">♧<i /></button><button className="new-button">＋ New mission</button></div>
        </header>

        <div className="preview-body">
          <div className="page-intro"><div><p className="eyebrow">{variant === "forensics" ? "LIVE INVESTIGATION" : "MONDAY, SEPTEMBER 8, 2025"}</p><h1>{variant === "minimal" ? "Missions" : "Good morning, Jean"}<span className="heading-muted">{variant === "minimal" ? " · 24 total" : ""}</span></h1><p className="subheading">{variant === "forensics" ? "Trace the evidence. Understand the exposure." : "Here&apos;s what needs your attention today."}</p></div><div className="variant-switcher">{variants.map((item) => <Link key={item.id} href={`/preview/${item.id}`} className={item.id === variant ? "selected" : ""}>{item.label}</Link>)}</div></div>

          {variant !== "minimal" && <div className="metric-grid"><Metric label="Open findings" value="19" change="↓ 12%" tone="orange" /><Metric label="Missions this week" value="24" change="↑ 28%" tone="violet" /><Metric label="Coverage" value="87.4%" change="↑ 4.2%" tone="green" /><Metric label="Mean time to review" value="2h 14m" change="↓ 18m" tone="blue" /></div>}

          <div className="workspace-grid">
            <section className="mission-card"><div className="section-heading"><div><h2>{variant === "forensics" ? "Evidence queue" : "Recent missions"}</h2><p>{variant === "forensics" ? "Prioritised by severity and confidence" : "Your latest security activity"}</p></div><button className="quiet-button">View all <span>→</span></button></div><div className="filters"><button className="filter active">All missions <span>24</span></button><button className="filter">Needs attention <span>8</span></button><button className="filter">Running <span>3</span></button><button className="filter">•••</button></div><div className="mission-list">{visibleMissions.map((mission) => { const index = missions.indexOf(mission); return <button key={mission.id} className={`mission-row ${selected === index ? "row-selected" : ""}`} onClick={() => setSelected(index)}><span className={`mission-icon ${statusClass(mission.status)}`}>{mission.status === "Running" ? "◌" : mission.status === "Failed" ? "!" : "✓"}</span><span className="mission-main"><strong>{mission.title}</strong><small>{mission.target}</small></span><span className={`status-dot ${statusClass(mission.status)}`} /> <span className="mission-status">{mission.status}</span><span className="finding-count">{mission.findings > 0 ? `${mission.findings} findings` : "Clear"}</span><span className="mission-time">{mission.time}</span><span className="row-arrow">›</span></button>; })}</div></section>
            <aside className="detail-card"><div className="detail-top"><span className="eyebrow">SELECTED MISSION</span><button className="quiet-button">•••</button></div><div className="detail-title"><span className="large-status completed">✓</span><div><h2>{activeMission.title}</h2><p>{activeMission.id} · {activeMission.time}</p></div></div><div className="detail-target"><span>⌁</span><div><small>Target</small><strong>{activeMission.target}</strong></div></div><div className="detail-divider" /><div className="detail-stats"><div><small>Findings</small><strong className={activeMission.findings ? "text-orange" : "text-green"}>{activeMission.findings}</strong></div><div><small>Providers</small><strong>8</strong></div><div><small>Duration</small><strong>04:32</strong></div></div><div className="coverage"><div><span>Coverage</span><strong>92%</strong></div><div className="progress"><i /></div></div><button className="open-detail">Open mission <span>↗</span></button></aside>
          </div>
        </div>
      </section>
    </main>
  );
}

function Metric({ label, value, change, tone }: Readonly<{ label: string; value: string; change: string; tone: string }>) { return <div className="metric"><div className={`metric-icon ${tone}`}>◒</div><div><span>{label}</span><strong>{value}</strong><small className={tone === "orange" ? "change-warn" : "change-good"}>{change} <em>vs last week</em></small></div></div>; }
