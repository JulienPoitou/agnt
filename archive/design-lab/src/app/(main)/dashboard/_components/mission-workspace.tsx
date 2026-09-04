"use client";

import { useRouter } from "next/navigation";

import type { ApiErrorBody, CapturedResponse, HistoryList, MissionDetail } from "@/lib/api";
import { MANIFEST, isApiError, isHistoryList, isMissionDetail } from "@/lib/api";

import type { ActiveView } from "./capture-notes";
import { MISSION_CASES, ROLE_LABELS, statusLabel, tokenLabel } from "./capture-notes";

interface Props {
  readonly captures: CapturedResponse[];
  readonly active: ActiveView | undefined;
}

export function MissionWorkspace({ captures, active }: Readonly<Props>) {
  const router = useRouter();
  const go = (key: string) => router.push(`/dashboard?v=${encodeURIComponent(key)}`);

  return (
    <div className="agnt-shell">
      <nav className="mission-index" aria-label="Matrice de captures gate-002">
        <div className="brand">
          AGNT <small>DESIGN LAB</small>
        </div>
        <div className="eyebrow">GATE-002 · RÉPONSES RÉELLES DE L'API CORE</div>
        <RailGroup
          title="LISTE & FILTRES"
          entries={captures.filter((c) => c.role !== "detail")}
          activeKey={active?.key}
          go={go}
        />
        <RailGroup
          title={`MISSIONS CAPTURÉES · ${captures.filter((c) => c.role === "detail").length}`}
          entries={captures.filter((c) => c.role === "detail")}
          activeKey={active?.key}
          go={go}
        />
        <div className="submission-note">
          <div className="eyebrow">MANIFESTE · SOUMISSION</div>
          <code>{MANIFEST.submission_id}</code>
          <p>
            {MANIFEST.submission_id !== "" && !MANIFEST.submission_id.startsWith("m-")
              ? "id transitoire de file : distinct de tout mission_id, ne singe pas le format « m-* » (cas submission_distinct)"
              : "anomalie : l'id de soumission imite un mission_id"}
          </p>
        </div>
      </nav>
      <main className="case">
        {active ? (
          <ResponsePanel view={active} captures={captures} go={go} />
        ) : (
          <IntroPanel captures={captures} go={go} />
        )}
      </main>
    </div>
  );
}

function RailGroup({
  title,
  entries,
  activeKey,
  go,
}: Readonly<{
  title: string;
  entries: CapturedResponse[];
  activeKey: string | undefined;
  go: (key: string) => void;
}>) {
  return (
    <div className="rail-group">
      <div className="eyebrow">{title}</div>
      {entries.map((c) => {
        const mission = isMissionDetail(c.body) ? c.body.mission : undefined;
        const isDetail = c.role === "detail" && mission !== undefined;
        const label = isDetail
          ? `${MISSION_CASES[mission.mission_id]?.cas ?? mission.mission_id}`
          : ROLE_LABELS[c.role]?.label ?? c.role;
        const sub = isDetail ? statusLabel(mission.status) : (ROLE_LABELS[c.role]?.note ?? c.path);
        return (
          <button
            key={c.body_file}
            className={activeKey === c.body_file ? "cap-btn on" : "cap-btn"}
            aria-current={activeKey === c.body_file ? "page" : undefined}
            onClick={() => go(isDetail ? mission.mission_id : c.body_file)}
            title={c.path}
          >
            <b>{label}</b>
            <span>{sub}</span>
          </button>
        );
      })}
    </div>
  );
}

function ResponseHeader({ view }: Readonly<{ view: ActiveView }>) {
  return (
    <div className="response-head">
      <div>
        <div className="eyebrow">RÉPONSE CAPTURÉE · {view.role}</div>
        <h1>GET {view.path}</h1>
      </div>
      <span className={view.status >= 400 ? "http http-err" : "http http-ok"}>
        HTTP {view.status} {view.status >= 400 ? "· refus de la requête" : "· OK"}
      </span>
    </div>
  );
}

function ResponsePanel({
  view,
  captures,
  go,
}: Readonly<{
  view: ActiveView;
  captures: CapturedResponse[];
  go: (id: string) => void;
}>) {
  if (isApiError(view.body)) return <ErrorPanel view={view} error={view.body} />;
  if (isHistoryList(view.body))
    return <HistoryPanel view={view} history={view.body} captures={captures} openDetail={go} />;
  if (isMissionDetail(view.body)) return <DetailPanel view={view} detail={view.body} />;
  return null;
}

function IntroPanel({
  captures,
  go,
}: Readonly<{ captures: CapturedResponse[]; go: (key: string) => void }>) {
  const first = captures[0];
  return (
    <div className="intro">
      <div className="eyebrow">MATRICE RÉELLE · GATE-002-PRODUCT-API</div>
      <h1>17 réponses HTTP réelles de l'API CORE, branchées une par une</h1>
      <p>
        16 cas de couverture complète sur 11 missions contrôlées, plus la liste, les filtres, la pagination et le
        refus 400. Chaque vue de ce labo est servie par SA capture, copiée octet pour octet de{" "}
        <code>docs/coordination/captures/gate-002-product-api/</code> (main). Aucune donnée n'est écrite à la main,
        aucune absence n'est rendue comme un zéro.
      </p>
      <button className="primary" onClick={() => first && go(first.body_file)}>
        Ouvrir la liste capturée →
      </button>
    </div>
  );
}

/* ---------- états de liste ---------- */

function HistoryPanel({
  view,
  history,
  captures,
  openDetail,
}: Readonly<{
  view: ActiveView;
  history: HistoryList;
  captures: CapturedResponse[];
  openDetail: (id: string) => void;
}>) {
  const roleNote = ROLE_LABELS[view.role]?.note;
  return (
    <>
      <ResponseHeader view={view} />
      <div className="meta-bar">
        <span>
          page.limit <b>{history.page.limit}</b>
        </span>
        <span>
          items <b>{history.items.length}</b>
        </span>
        <span>
          next_cursor{" "}
          <b>
            {history.page.next_cursor === null ? (
              "null · page finale"
            ) : (
              <code className="cursor" title={history.page.next_cursor}>
                {history.page.next_cursor.slice(0, 28)}…
              </code>
            )}
          </b>
        </span>
        {roleNote && <em className="role-note">{roleNote}</em>}
      </div>
      {history.items.length === 0 ? (
        <div className="empty-state">
          <div className="eyebrow">ÉTAT · LISTE RÉELLEMENT VIDE</div>
          <h2>Aucune mission ne correspond — et c'est un succès HTTP 200</h2>
          <p>
            Cette capture est <code>GET /api/missions?limit=25&amp;status=en_file</code> : la liste est vide parce
            qu'aucune mission n'est en file. Le front distingue : liste vide ≠ erreur, ≠ refus, ≠ « zéro finding »
            d'une mission. <code>items: []</code> est publié, pas remplacé.
          </p>
        </div>
      ) : (
        <div className="mission-rows" role="list">
          {history.items.map((m) => {
            const findingCount = m.findings_summary ? String(m.findings_summary.total) : "inconnu";
            const hasDetail = captures.some(
              (c) => c.role === "detail" && isMissionDetail(c.body) && c.body.mission.mission_id === m.mission_id
            );
            return (
              <button
                key={m.mission_id}
                role="listitem"
                onClick={() => openDetail(m.mission_id)}
                disabled={!hasDetail}
                title={hasDetail ? `Ouvrir la capture détail de ${m.mission_id}` : "aucune capture détail pour cette mission"}
              >
                <b>{m.request.title}</b>
                <span className="cell-target">
                  {m.target.type} · {m.target.display_name}
                </span>
                <span className={"status " + m.status}>{statusLabel(m.status)}</span>
                <span className="cell-count">
                  findings <b>{findingCount}</b>
                </span>
                <span className="cell-run">{m.run_id ?? "aucun run publié"}</span>
              </button>
            );
          })}
        </div>
      )}
    </>
  );
}

function ErrorPanel({ view, error }: Readonly<{ view: ActiveView; error: ApiErrorBody }>) {
  return (
    <>
      <ResponseHeader view={view} />
      <div className="err-state">
        <div className="eyebrow">ÉTAT · REQUÊTE REFUSÉE AVANT EXÉCUTION</div>
        <h2>
          {error.error.code} — le filtre demandé n'existe pas
        </h2>
        <p>
          Ce n'est ni une liste vide, ni une mission en échec : la requête elle-même est invalide et l'API le dit,
          avec le vocabulaire admis en clair. Le front affiche le message verbatim de la capture.
        </p>
        <blockquote>{error.error.message}</blockquote>
      </div>
    </>
  );
}

/* ---------- état de détail ---------- */

function DetailPanel({ view, detail }: Readonly<{ view: ActiveView; detail: MissionDetail }>) {
  const m = detail.mission;
  const d = detail.data;
  const cased = MISSION_CASES[m.mission_id];
  const summary = m.findings_summary;
  const semgrepish = d.executions.length;
  const zeroProved = summary?.total === 0 && d.executions.some((x) => x.detection.value === "rien_trouve");
  return (
    <>
      <ResponseHeader view={view} />
      <header className="case-head">
        <div>
          <div className="eyebrow">MISSION / {m.mission_id}</div>
          <h1>{m.request.title}</h1>
          <p>
            {m.target.type} · {m.target.display_name} · run {m.run_id ?? "aucun run_id publié"} ·{" "}
            {m.duration_ms !== undefined ? `${m.duration_ms} ms` : "durée non consignée"}
          </p>
        </div>
        <div className="case-status">
          <span className={"status large " + m.status}>{statusLabel(m.status)}</span>
          {cased && (
            <div className="case-note">
              <b>cas {cased.cas}</b>
              <span>{cased.fait}</span>
            </div>
          )}
        </div>
      </header>
      <section className="coverage">
        <div>
          <label>FINDINGS</label>
          <strong>{summary ? summary.total : "inconnu"}</strong>
          <small>{summary ? "compte consigné" : "aucun compte publié dans cette capture — non consigné ≠ zéro"}</small>
        </div>
        <div>
          <label>CORRÉLATIONS</label>
          <strong>{m.clusters_count ?? "inconnu"}</strong>
          <small>{m.clusters_count === undefined ? "clusters_count non publié" : "compte consigné"}</small>
        </div>
        <div>
          <label>PROVIDERS</label>
          <strong>{semgrepish}</strong>
          <small>agnt.execution-status.v1</small>
        </div>
        <div>
          <label>TIMELINE</label>
          <strong>
            {d.timeline.returned_events}/{d.timeline.total_events}
          </strong>
          <small>
            legacy events {d.events.length} · compteurs indépendants, jamais fusionnés
          </small>
        </div>
      </section>
      {zeroProved && (
        <div className="proof-strip">
          Zéro finding <b>prouvé</b> ici : {d.executions
            .filter((x) => x.detection.value === "rien_trouve")
            .map((x) => `${x.display_name} (cibles analysées : ${x.detection.analyzed_targets ?? "?"})`)
            .join(", ")}
          {" — "}complétude{" "}
          {d.executions.every((x) => x.completeness.state === "complete") ? "complète" : "partielle"}. Un zéro sans
          ces preuves ne serait pas affiché comme un succès.
        </div>
      )}
      {detail.missing_artifacts.length > 0 && (
        <div className="missing-strip">
          <span className="eyebrow">ARTÉFACTS MANQUANTS — DONNÉES JAMAIS FABRIQUÉES PAR LE FRONT</span>
          <ul>
            {detail.missing_artifacts.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </div>
      )}
      <section className="content-grid">
        <div>
          <FindingsSection detail={detail} />
          <ExecutionsSection detail={detail} />
          {d.plan && <PlanSection plan={d.plan} />}
          {d.intent && (
            <div className="kv-block">
              <div className="section-title">
                <h2>Intent</h2>
                <span>consigné seq {d.intent.seq}</span>
              </div>
              <dl>
                <dt>statut</dt>
                <dd>{d.intent.statut}</dd>
                <dt>capacités</dt>
                <dd>{d.intent.capabilities.join(", ")}</dd>
              </dl>
            </div>
          )}
        </div>
        <aside className="report">
          <div className="eyebrow">REPORT · agnt.history.v1</div>
          {d.report ? (
            <>
              <h2>{d.report.available ? "Rapport publié dans la capture" : "available: false — pas de rapport"}</h2>
              <p>{d.report.format ? `format ${d.report.format}` : "format non publié"}</p>
              {d.report.content && <pre className="report-content">{d.report.content}</pre>}
            </>
          ) : (
            <h2>Aucun rapport publié dans cette capture</h2>
          )}
          <div className="eyebrow timeline-label">COUVERTURE</div>
          {d.coverage ? (
            <pre className="json-block">{JSON.stringify(d.coverage, null, 1)}</pre>
          ) : (
            <p className="absent">coverage non publiée — le front ne déduit rien</p>
          )}
          <TimelineSection detail={detail} />
        </aside>
      </section>
    </>
  );
}

function FindingsSection({ detail }: Readonly<{ detail: MissionDetail }>) {
  const findings = detail.data.findings;
  return (
    <div className="section-title-wrap">
      <div className="section-title">
        <h2>Findings</h2>
        <span>{findings ? `tableau publié · ${findings.length}` : "tableau absent de la réponse — non consigné"}</span>
      </div>
      {findings && findings.length > 0 ? (
        <div className="finding-table">
          {findings.map((f) => (
            <div key={f.identity.fingerprint} className="finding-row">
              <span className={"severity " + f.severity.value.toLowerCase()}>{f.severity.value}</span>
              <strong>{f.evidence.title}</strong>
              <span className="cell-tool">{f.source.tool}</span>
              <code>
                {f.location.asset} · {f.location.file}:{f.location.line}
              </code>
              <p className="finding-desc">
                {f.evidence.description} · origine {f.severity.origine} · règle {f.identity.canonical_rule_id}
              </p>
            </div>
          ))}
        </div>
      ) : findings ? (
        <p className="absent">Le tableau publié est vide : cette mission ne rapporte aucun finding.</p>
      ) : (
        <p className="absent">
          Aucun tableau de findings dans cette réponse. Ce n'est PAS un zéro : le front distingue « rien trouvé
          (prouvé) » de « non consigné ».
        </p>
      )}
      {detail.data.clusters && (
        <p className="clusters-line">
          clusters : {detail.data.clusters.clusters.length} publié(s) ({detail.data.clusters.clusters
            .map((c) => c.cluster_id)
            .join(", ") || "aucun"}) · non regroupés {detail.data.clusters.non_regroupe.length}
        </p>
      )}
    </div>
  );
}

const DIMENSIONS = [
  ["applicability", "Applicabilité"],
  ["selection", "Sélection"],
  ["condition", "Condition"],
  ["authorization", "Autorisation"],
  ["availability", "Disponibilité"],
  ["execution", "Exécution"],
  ["detection", "Détection"],
] as const;

function ExecutionsSection({ detail }: Readonly<{ detail: MissionDetail }>) {
  return (
    <div>
      <div className="section-title">
        <h2>Executions</h2>
        <span>{detail.data.execution_status_schema} · chaque dimension de décision reste distincte</span>
      </div>
      <div className="execution-list">
        {detail.data.executions.map((x) => (
          <div key={x.provider_id} className="exec">
            <div className="exec-head">
              <strong>{x.display_name}</strong>
              <span className="cell-run">{x.provider_id}</span>
              {x.capability_id && <span className="chip">{x.capability_id}</span>}
              <span className={"status " + x.execution.value}>{tokenLabel(x.execution.value)}</span>
            </div>
            <div className="dim-grid">
              {DIMENSIONS.map(([key, label]) => {
                const block = x[key];
                return (
                  <div key={key} className="dim">
                    <label>{label}</label>
                    <b>{tokenLabel(block.value)}</b>
                    <small>
                      {tokenLabel(block.proof)}
                      {block.reason_code ? ` · ${block.reason_code}` : ""}
                    </small>
                    {key === "execution" && (
                      <small>
                        invocation {x.execution.invocation} · sortie {x.execution.output}
                      </small>
                    )}
                    {key === "detection" && (
                      <small>
                        {x.detection.findings_count !== undefined
                          ? `findings ${x.detection.findings_count}`
                          : "aucun compte publié"}
                        {x.detection.analyzed_targets !== undefined
                          ? ` · cibles analysées ${x.detection.analyzed_targets}`
                          : ""}
                      </small>
                    )}
                    {key === "applicability" && block.value === "non_applicable" && (
                      <small>écarté à l'applicabilité — jamais compté comme zéro</small>
                    )}
                    {key === "detection" && block.value === "non_evalue" && (
                      <small>non évalué : pas de findings, pas de « rien trouvé »</small>
                    )}
                  </div>
                );
              })}
              <div className="dim">
                <label>Complétude</label>
                <b>{tokenLabel(x.completeness.state)}</b>
                <small>
                  {x.completeness.missing.length > 0 ? `manquants : ${x.completeness.missing.join(", ")}` : ""}
                  {x.completeness.limitations.length > 0
                    ? `${x.completeness.missing.length > 0 ? " · " : ""}limitations : ${x.completeness.limitations.join(", ")}`
                    : x.completeness.missing.length === 0
                      ? "aucune limitation consignée"
                      : ""}
                </small>
              </div>
            </div>
            {x.provenance && (
              <details className="prov">
                <summary>
                  provenance consignée · {String(x.provenance.provider_kind ?? "provider_kind absent")} (allowlist
                  projetée, jamais devinée)
                </summary>
                <pre className="json-block">{JSON.stringify(x.provenance, null, 1)}</pre>
              </details>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function PlanSection({ plan }: Readonly<{ plan: NonNullable<MissionDetail["data"]["plan"]> }>) {
  return (
    <div>
      <div className="section-title">
        <h2>Plan</h2>
        <span>{plan.plan_id}</span>
      </div>
      <div className="plan-steps">
        {plan.steps.map((s) => (
          <div key={`${s.provider}-${s.capability}`}>
            <strong>{s.provider}</strong>
            <span>{s.capability}</span>
            <span className="chip">{s.risque}</span>
            <span>sorties {s.sorties.length}</span>
          </div>
        ))}
      </div>
      <p className="absent">
        champs publiés à null : cree_le {String(plan.cree_le)} · moteur_intent {String(plan.moteur_intent)} ·
        request_id {String(plan.request_id)} · requete_canonique {String(plan.requete_canonique)} — null est une
        valeur consignée, pas une absence inventée
      </p>
    </div>
  );
}

function TimelineSection({ detail }: Readonly<{ detail: MissionDetail }>) {
  const t = detail.data.timeline;
  return (
    <div>
      <div className="eyebrow timeline-label">TIMELINE · agnt.timeline.v1</div>
      <p className="tl-meta">
        {t.state} · {t.ordering} · renvoyés {t.returned_events}/{t.total_events} · tronqué {String(t.truncated)} ·
        next_cursor {t.next_cursor === null ? "null" : "publié"}
        {t.limitations.length > 0 ? ` · limitations : ${t.limitations.join(", ")}` : ""}
      </p>
      {t.events.map((e) => (
        <div className={"event" + (e.data_state === "unavailable" ? " event-partial" : "")} key={e.event_id}>
          <span>
            {e.kind} <i className="tl-cat">{e.category}</i>
          </span>
          <small>
            seq {e.position} · {e.safe_summary}
          </small>
          <small className="tl-sub">
            {tokenLabel(e.consequence)} · data_state {tokenLabel(e.data_state)} · visibilité {e.visibility} · source{" "}
            {e.source.kind}#{e.source.sequence}
            {e.source.source_kind ? ` (source_kind: ${e.source.source_kind})` : ""}
            {e.limitations.length > 0 ? ` · ${e.limitations.join(", ")}` : ""}
          </small>
          {e.kind === "unknown_event_recorded" && (
            <small className="tl-warn">événement non reconnu du lecteur — le payload n'est jamais publié</small>
          )}
        </div>
      ))}
      <p className="tl-legacy">journal legacy data.events : {detail.data.events.length} événements · journal timeline : {t.total_events} — le front n'en fait jamais une somme</p>
    </div>
  );
}
