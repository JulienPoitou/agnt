import { NavLink } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  Boxes,
  FileText,
  LayoutGrid,
  Plus,
  Radio,
  Server,
  Settings,
  ShieldAlert,
  Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useVersion } from "@/api/queries";
import { useI18n } from "@/i18n";

const NAV: { to: string; labelKey: string; icon: typeof LayoutGrid; end?: boolean }[] = [
  { to: "/", labelKey: "nav.overview", icon: LayoutGrid, end: true },
  { to: "/scans/new", labelKey: "nav.newScan", icon: Plus },
  { to: "/scans", labelKey: "nav.scans", icon: Target },
  { to: "/instances", labelKey: "nav.instances", icon: Server },
  { to: "/findings", labelKey: "nav.findings", icon: ShieldAlert },
  { to: "/live", labelKey: "nav.live", icon: Radio },
  { to: "/reports", labelKey: "nav.reports", icon: FileText },
  // Schedules / Email Triage : le moteur AGNT n'a ni planification ni triage de
  // courriel — masquées plutôt que servies vides. /capacites remplace Integrations.
  { to: "/capacites", labelKey: "nav.capacites", icon: Boxes },
  { to: "/settings", labelKey: "nav.settings", icon: Settings },
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useI18n();
  const { data: version } = useVersion();
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-card">
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <div className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-md border border-border bg-background">
          <span aria-hidden className="flex h-full w-full items-center justify-center bg-accent text-xs font-bold text-accent-foreground">A</span>
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold tracking-tight">AGNT</span>
          <span className="text-[10px] text-muted-foreground mono">
            {version?.version ? `v${version.version}` : t("sidebar.securityScanner")}
          </span>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto py-3" aria-label="Primary">
        <ul className="space-y-0.5 px-2">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                      isActive
                        ? "bg-accent text-accent-foreground"
                        : "text-muted-foreground hover:bg-accent/40 hover:text-foreground",
                    )
                  }
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                  <span>{t(item.labelKey)}</span>
                </NavLink>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="border-t border-border px-4 py-3 text-[10px] text-muted-foreground mono">
        <div className="flex items-center gap-1.5">
          <Activity className="h-3 w-3" aria-hidden />
          <span>{t("sidebar.localScanner")}</span>
        </div>
        <div className="mt-1 flex items-center gap-1.5 opacity-70">
          <AlertOctagon className="h-3 w-3" aria-hidden />
          <span>{t("sidebar.commandHint")}</span>
        </div>
      </div>
    </aside>
  );
}
