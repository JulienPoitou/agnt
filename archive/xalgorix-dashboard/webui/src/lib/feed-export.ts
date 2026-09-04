import type { FeedEvent } from "@/store/ws";

export type FeedExportFormat = "json" | "jsonl" | "txt";

export interface FeedExportOptions {
  events: FeedEvent[];
  format: FeedExportFormat;
  filenamePrefix?: string;
  metadata?: Record<string, unknown>;
}

type ExportableFeedEvent = Omit<FeedEvent, "_key" | "_receivedAt"> & {
  received_at?: string;
};

export function exportFeedEvents({
  events,
  format,
  filenamePrefix = "xalgorix-live-feed",
  metadata = {},
}: FeedExportOptions) {
  if (events.length === 0 || typeof document === "undefined") return;

  const exportedAt = new Date();
  const cleanEvents = events.map(toExportableEvent);
  const baseName = [
    safeFilenamePart(filenamePrefix),
    safeFilenamePart(String(metadata.filter || "all")),
    timestampForFilename(exportedAt),
  ]
    .filter(Boolean)
    .join("-");

  const payload = buildPayload(cleanEvents, format, exportedAt, metadata);
  downloadTextFile(`${baseName}.${format}`, payload.body, payload.mimeType);
}

function toExportableEvent(event: FeedEvent): ExportableFeedEvent {
  const { _key, _receivedAt, ...rest } = event;
  return {
    ...rest,
    received_at: Number.isFinite(_receivedAt)
      ? new Date(_receivedAt).toISOString()
      : undefined,
  };
}

function buildPayload(
  events: ExportableFeedEvent[],
  format: FeedExportFormat,
  exportedAt: Date,
  metadata: Record<string, unknown>,
): { body: string; mimeType: string } {
  switch (format) {
    case "jsonl":
      return {
        body: events.map((event) => JSON.stringify(event)).join("\n") + "\n",
        mimeType: "application/x-ndjson;charset=utf-8",
      };
    case "txt":
      return {
        body: buildTranscript(events, exportedAt, metadata),
        mimeType: "text/plain;charset=utf-8",
      };
    case "json":
    default:
      return {
        body: JSON.stringify(
          {
            source: "xalgorix-live-feed",
            exported_at: exportedAt.toISOString(),
            count: events.length,
            ...metadata,
            events,
          },
          null,
          2,
        ),
        mimeType: "application/json;charset=utf-8",
      };
  }
}

function buildTranscript(
  events: ExportableFeedEvent[],
  exportedAt: Date,
  metadata: Record<string, unknown>,
): string {
  const lines = [
    "Xalgorix live feed export",
    `Exported: ${exportedAt.toISOString()}`,
    `Events: ${events.length}`,
  ];

  if (metadata.scope) lines.push(`Scope: ${metadata.scope}`);
  if (metadata.filter) lines.push(`Filter: ${metadata.filter}`);
  lines.push("");

  for (const event of events) {
    const timestamp = event.timestamp || event.received_at || "";
    const label = [event.type || "event", event.tool_name]
      .filter(Boolean)
      .join(" ");
    const message =
      event.content || event.output || event.error || event.target || "";

    lines.push(`[${timestamp}] ${label}`);
    if (message) lines.push(indent(message));
    if (event.tool_args && Object.keys(event.tool_args).length > 0) {
      lines.push(indent(`args: ${JSON.stringify(event.tool_args)}`));
    }
    if (event.error && event.error !== message) {
      lines.push(indent(`error: ${event.error}`));
    }
    if (event.vulns && event.vulns.length > 0) {
      lines.push(indent(`vulns: ${JSON.stringify(event.vulns, null, 2)}`));
    }
    lines.push("");
  }

  return lines.join("\n");
}

function indent(value: string): string {
  return value
    .split(/\r?\n/)
    .map((line) => `  ${line}`)
    .join("\n");
}

function downloadTextFile(filename: string, body: string, mimeType: string) {
  const blob = new Blob([body], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function safeFilenamePart(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function timestampForFilename(date: Date): string {
  return date.toISOString().replace(/[:.]/g, "-");
}
