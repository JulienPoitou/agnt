import { useState } from "react";

export default function WebScan() {
  const [url, setUrl] = useState("https://example.com");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const valid = (() => {
    try {
      const u = new URL(url);
      return u.protocol === "https:" || u.protocol === "http:";
    } catch { return false; }
  })();

  async function lancer() {
    if (!valid) return;
    setLoading(true);
    try {
      const res = await fetch("/api/engagements/web", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          cible_autorisee: [new URL(url).hostname],
          providers: { httpx: true, katana: true, ffuf: false, nuclei: true },
          tags: ["cve", "exposure", "misconfig"],
          severity_min: "high",
          intensity: "normal",
          egress: true,
          strict_scope: true,
        }),
      });
      const data = await res.json();
      setResult(data);
    } catch (e: any) {
      setResult({ error: String(e) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="web-scan">
      <h2>Web Pentest — V1 Black-Box</h2>
      <p className="lead">Scanne une web app externe via la console. Egress et scope RDN explicites, Oracle http_response.</p>
      <div className="kbar" style={{ gap: 12 }}>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://target.tld"
          style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: "1px solid #1e293b", background: "#020617", color: "#e2e8f0" }}
        />
        <button className="btn" onClick={lancer} disabled={!valid || loading} style={{ opacity: !valid || loading ? 0.5 : 1 }}>
          {loading ? "lancement..." : "lancer scan →"}
        </button>
      </div>
      {!valid && <p style={{ color: "#ef4444", marginTop: 8 }}>URL invalide — doit être https:// ou http://</p>}
      <div className="chips" style={{ marginTop: 12 }}>
        <span className="chip"><i /> httpx</span>
        <span className="chip"><i /> katana</span>
        <span className="chip"><i /> nuclei</span>
        <span className="chip">scope RDN strict</span>
        <span className="chip">egress: true</span>
      </div>
      {result && (
        <pre style={{ marginTop: 16, padding: 12, background: "#020617", borderRadius: 8, overflow: "auto", fontSize: 12 }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
      <div className="foot" style={{ marginTop: 24 }}>
        <span>Branche <b>feat/web-pentest-console-v1</b> depuis <b>a7ec46f</b> — main gelé</span>
      </div>
    </div>
  );
}
