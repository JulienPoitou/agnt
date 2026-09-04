import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDuration(startISO: string, endISO?: string): string {
  if (!startISO) return "—";
  const start = new Date(startISO).getTime();
  if (Number.isNaN(start)) return "—";
  const end = endISO ? new Date(endISO).getTime() : Date.now();
  if (Number.isNaN(end)) return "—";
  const ms = Math.max(0, end - start);
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function timeAgo(iso?: string): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const diff = Date.now() - t;
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export function formatTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function shortId(id?: string, n = 7): string {
  if (!id) return "—";
  return id.length > n ? id.slice(0, n) : id;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export function normalizeSeverity(s?: string): Severity {
  const v = (s || "").toLowerCase().trim();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium" || v === "moderate") return "medium";
  if (v === "low") return "low";
  return "info";
}

export function severityRank(s?: string): number {
  switch (normalizeSeverity(s)) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Shared Radix DropdownMenu content class (popover panel). */
export const menuContentClass =
  "z-50 min-w-44 rounded-md border border-border bg-popover p-1 text-sm text-popover-foreground shadow-md";

/** Shared Radix DropdownMenu item class (single row). */
export const menuItemClass =
  "flex w-full cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm outline-none transition-colors hover:bg-accent focus:bg-accent";
