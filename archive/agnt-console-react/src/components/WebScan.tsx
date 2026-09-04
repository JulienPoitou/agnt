import { useState } from "react";

const PROVIDERS = ["httpx", "katana", "ffuf", "nuclei"] as const;

type ProviderId = (typeof PROVIDERS)[number];

export default function WebScan() {
  const [url, setUrl] = useState("https://example.com");
  const [autorisee, setAutorisee] = useState(false);
  const [choisis, setChoisis] = useState<Record<ProviderId, boolean>>({
    httpx: true, katana: true, ffuf: true, nuclei: true,
  });
  const [intensity, setIntensity] = useState<"normal" | "aggressive">("normal");
  const [egress, setEgress] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const valid = (() => {
    try {
      const u = new URL(url.trim());
      return u.protocol === "https:" || u.protocol === "http:";
    } catch { return false; }
  })();

  const peutLancer = valid && autorisee && !loading
    && (Object.values(choisis) as boolean[]).some(Boolean);

  function bascule(p: ProviderId) {
    setChoisis((c) => ({ ...c, [p]: !c[p] }));
  }

  async function lancer() {
    if (!peutLancer) return;
    setLoading(true);
    try {
      const res = await fetch("/api/engagements/web", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url.trim(),
          cible_autorisee: true,
          providers: (Object.keys(choisis) as ProviderId[]).filter((p) => choisis[p]),
          intensity,
          egress,
        }),
      });
      const data = await res.json();
      let full = { http: res.status, ...data };
      if (res.ok && (data as any).id) {
        try {
          const det = await fetch(`/api/runs/${(data as any).id}`);
          const detJson = await det.json();
          if (det.ok && (detJson as any).preuve) full = { ...full, preuve: (detJson as any).preuve };
        } catch { /* la preuve reste absente, le plan reste affiché */ }
      }
      setResult(full);
    } catch (e: any) {
      setResult({ error: String(e) });
    } finally {
      setLoading(false);
    }
  }

  const engagement = result && !result.error && (result.statut === "planifie" || result.id) ? result : null;
  const erreur = result && (result.error || result.erreur) ? (result.error ?? result.erreur) : null;

  return (
    <div className="web-scan">
      <h2>Web Pentest — V1 Black-Box</h2>
      <p className="lead">Scanne une web app externe via la console. Egress et scope explicites, Oracle http_response, preuve scellée.</p>
      <div className="kbar" style={{ gap: 12 }}>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://target.tld"
          style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: "1px solid #1e293b", background: "#020617", color: "#e2e8f0" }}
        />
        <button className="btn" onClick={lancer} disabled={!peutLancer} style={{ opacity: !peutLancer ? 0.5 : 1 }}>
          {loading ? "lancement..." : "lancer scan →"}
        </button>
      </div>
      {!valid && <p style={{ color: "#ef4444", marginTop: 8 }}>URL invalide — doit être https:// ou http://</p>}
      <label style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "flex-start", cursor: "pointer" }}>
        <input type="checkbox" checked={autorisee} onChange={(e) => setAutorisee(e.target.checked)} style={{ marginTop: 4 }} />
        <span>Je suis autorisé à tester cette cible <b>(obligatoire — sans ça, le moteur refuse en 403)</b></span>
      </label>
      <div className="chips" style={{ marginTop: 12 }}>
        {PROVIDERS.map((p) => (
          <label key={p} className="chip" style={{ cursor: "pointer" }}>
            <input type="checkbox" checked={choisis[p]} onChange={() => bascule(p)} /> {p}
          </label>
        ))}
        <label className="chip">
          intensité&nbsp;
          <select value={intensity} onChange={(e) => setIntensity(e.target.value as "normal" | "aggressive")}>
            <option value="normal">normal (replay ×3)</option>
            <option value="aggressive">aggressive (replay ×5)</option>
          </select>
        </label>
        <label className="chip" style={{ cursor: "pointer" }}>
          <input type="checkbox" checked={egress} onChange={(e) => setEgress(e.target.checked)} /> egress
        </label>
      </div>
      {erreur && (
        <p style={{ color: "#ef4444", marginTop: 12 }}>
          Refusé : {typeof erreur === "string" ? erreur : JSON.stringify(erreur)}
          {result && result.admises ? ` — admis : ${(result.admises as string[]).join(", ")}` : ""}
        </p>
      )}
      {engagement && (
        <div style={{ marginTop: 16, padding: 12, background: "#020617", borderRadius: 8, fontSize: 13 }}>
          <p><b>Engagement {engagement.deduplique ? "déjà planifié" : "planifié"}</b> — <code>{engagement.url_canonique ?? engagement.url_sure}</code></p>
          <p>Chaîne : {(engagement.providers_prevus as string[] ?? []).join(" → ")} · Oracle {(engagement.verification as any)?.oracle} (replay ×{(engagement.verification as any)?.replay})</p>
          <p>Exécution : <b>{engagement.execution}</b> — {(engagement.limites_connues as string[] ?? []).join(" · ")}</p>
          {engagement.preuve ? <p>Preuve : <code>{(engagement.preuve as any).empreinte?.slice(0, 20)}…</code> (sha256, vérifiable)</p> : null}
        </div>
      )}
      {result && (
        <pre style={{ marginTop: 16, padding: 12, background: "#020617", borderRadius: 8, overflow: "auto", fontSize: 12 }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
      <div className="foot" style={{ marginTop: 24 }}>
        <span>Engagements web : validation stricte, autorisation explicite, preuve scellée — exécution réelle au prochain milestone</span>
      </div>
    </div>
  );
}
