import { cn } from "@/lib/utils";

// Xalgorix 22-phase methodology. The backend reports `current_phase` and
// `phases` as 1-based ids into this list, and the New Scan form lets the
// operator opt into any subset. Keeping a single source of truth here
// prevents the dashboard from drifting out of sync with the scan form.
export const PHASES: { id: number; name: string }[] = [
  { id: 1, name: "Reconnaissance" },
  { id: 2, name: "Manual Vuln Discovery" },
  { id: 3, name: "Directory & File Discovery" },
  { id: 4, name: "CORS & Cookies" },
  { id: 5, name: "Auth & Session" },
  { id: 6, name: "Injection" },
  { id: 7, name: "SSRF" },
  { id: 8, name: "IDOR / BAC" },
  { id: 9, name: "API & GraphQL" },
  { id: 10, name: "File Upload" },
  { id: 11, name: "Deserialization & RCE" },
  { id: 12, name: "Race & Business Logic" },
  { id: 13, name: "Subdomain Takeover" },
  { id: 14, name: "Open Redirect" },
  { id: 15, name: "Email Security" },
  { id: 16, name: "Cloud & Infrastructure" },
  { id: 17, name: "WebSocket" },
  { id: 18, name: "CMS-Specific" },
  { id: 19, name: "Broken Links & Spoofing" },
  { id: 20, name: "Exploit Verification" },
  { id: 21, name: "Zero-Day Discovery" },
  { id: 22, name: "Final Report" },
];

export function PhaseProgress({
  current,
  selected,
  status,
  className,
}: {
  current?: number;
  selected?: number[];
  status?: string;
  className?: string;
}) {
  const isRunning = (status || "").toLowerCase() === "running";
  const selectedSet = new Set(
    selected && selected.length ? selected : PHASES.map((p) => p.id),
  );
  return (
    <div
      className={cn("flex items-center gap-1", className)}
      role="progressbar"
      aria-valuemin={1}
      aria-valuemax={PHASES.length}
      aria-valuenow={current ?? undefined}
      aria-label="Scan phase progress"
    >
      {PHASES.map((p) => {
        const isSelected = selectedSet.has(p.id);
        const isCurrent = isRunning && current === p.id;
        const isPassed = current ? p.id < current : false;
        return (
          <div
            key={p.id}
            title={`${p.id}. ${p.name}`}
            className={cn(
              "h-1.5 flex-1 rounded-sm transition-colors",
              !isSelected && "bg-muted/40",
              isSelected && !isPassed && !isCurrent && "bg-muted",
              isPassed && "bg-emerald-500/70",
              isCurrent && "bg-amber-400 pulse-dot",
            )}
          />
        );
      })}
    </div>
  );
}
