import { create } from "zustand";
import type { WSEvent } from "@/types/api";

export type WSStatus =
  | "idle"
  | "connecting"
  | "connected"
  | "disconnected"
  | "reconnecting";

export interface FeedEvent extends WSEvent {
  // client-side dedupe key + ordering
  _key: string;
  _receivedAt: number;
}

interface WSState {
  status: WSStatus;
  lastError?: string;
  events: FeedEvent[];
  paused: boolean;
  maxEvents: number;
  subscribedInstance?: string;

  // actions
  setStatus: (s: WSStatus, err?: string) => void;
  pushEvent: (e: WSEvent) => void;
  clearEvents: () => void;
  setPaused: (p: boolean) => void;
  subscribe: (instanceId: string) => void;
  unsubscribe: () => void;

  // internals
  _socket?: WebSocket;
  _reconnectTimer?: ReturnType<typeof setTimeout>;
  _reconnectAttempts: number;
  connect: () => void;
  disconnect: () => void;
}

export function parsedEventTimestampMs(timestamp?: string): number | undefined {
  if (!timestamp) return undefined;
  const ms = Date.parse(timestamp);
  return Number.isFinite(ms) ? ms : undefined;
}

export function eventOrderMs(event: FeedEvent): number {
  return parsedEventTimestampMs(event.timestamp) ?? event._receivedAt ?? 0;
}

export function eventDedupeKey(e: WSEvent, fallbackTs = 0): string {
  const ts = e.timestamp || String(fallbackTs || "");
  const tool = e.tool_name || "";
  const msg = e.content || e.output || e.error || "";
  const instance = e.instance_id || "";
  // Truncate message so the dedupe key stays small
  return `${ts}|${instance}|${e.type}|${tool}|${msg.slice(0, 80)}`;
}

export function toFeedEvent(
  e: WSEvent,
  source = "event",
  index = 0,
): FeedEvent {
  const receivedAt = parsedEventTimestampMs(e.timestamp) ?? Date.now();
  const dedupeKey = eventDedupeKey(e, receivedAt);
  return {
    ...e,
    _key: `${source}:${index}:${dedupeKey}`,
    _receivedAt: receivedAt,
  };
}

export function mergeFeedEvents(...streams: FeedEvent[][]): FeedEvent[] {
  const seen = new Set<string>();
  const out: FeedEvent[] = [];
  for (const events of streams) {
    for (const event of events) {
      const key = eventDedupeKey(event, event._receivedAt);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(event);
    }
  }
  return out.sort((a, b) => {
    const byTime = eventOrderMs(a) - eventOrderMs(b);
    if (byTime !== 0) return byTime;
    const byReceived = (a._receivedAt || 0) - (b._receivedAt || 0);
    if (byReceived !== 0) return byReceived;
    return a._key.localeCompare(b._key);
  });
}

const WS_URL = () => {
  if (typeof window === "undefined") return "";
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws`;
};

export const useWSStore = create<WSState>((set, get) => ({
  status: "idle",
  events: [],
  paused: false,
  maxEvents: 1000,
  _reconnectAttempts: 0,

  setStatus: (s, err) => set({ status: s, lastError: err }),

  pushEvent: (e) => {
    if (get().paused) return;
    const receivedAt = Date.now();
    const key = eventDedupeKey(e, receivedAt);
    set((state) => {
      // dedupe by key (last 200 keys are enough)
      const recent = state.events.slice(-200);
      if (recent.some((x) => x._key === key)) return state;
      const next: FeedEvent = { ...e, _key: key, _receivedAt: receivedAt };
      const events = [...state.events, next];
      // cap size
      if (events.length > state.maxEvents) {
        events.splice(0, events.length - state.maxEvents);
      }
      return { events };
    });
  },

  clearEvents: () => set({ events: [] }),
  setPaused: (p) => set({ paused: p }),

  subscribe: (instanceId) => {
    set({ subscribedInstance: instanceId });
    const sock = get()._socket;
    if (sock && sock.readyState === WebSocket.OPEN) {
      sock.send(JSON.stringify({ subscribe: instanceId }));
    }
  },

  unsubscribe: () => {
    set({ subscribedInstance: undefined });
    const sock = get()._socket;
    if (sock && sock.readyState === WebSocket.OPEN) {
      sock.send(JSON.stringify({ unsubscribe: true }));
    }
  },

  connect: () => {
    if (typeof window === "undefined") return;
    const existing = get()._socket;
    if (
      existing &&
      (existing.readyState === WebSocket.OPEN ||
        existing.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    const attempt = get()._reconnectAttempts;
    set({ status: attempt > 0 ? "reconnecting" : "connecting" });

    let sock: WebSocket;
    try {
      sock = new WebSocket(WS_URL());
    } catch (err) {
      set({
        status: "disconnected",
        lastError: err instanceof Error ? err.message : "WebSocket error",
      });
      scheduleReconnect(get);
      return;
    }

    sock.onopen = () => {
      set({ status: "connected", _reconnectAttempts: 0, lastError: undefined });
      // re-subscribe to instance if we were subscribed before disconnect
      const inst = get().subscribedInstance;
      if (inst) {
        try {
          sock.send(JSON.stringify({ subscribe: inst }));
        } catch {
          /* ignore */
        }
      }
    };

    sock.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data) as WSEvent;
        get().pushEvent(data);
      } catch {
        // ignore malformed events
      }
    };

    sock.onerror = () => {
      set({ status: "disconnected", lastError: "Connection error" });
    };

    sock.onclose = () => {
      set({ status: "disconnected" });
      scheduleReconnect(get);
    };

    set({ _socket: sock });
  },

  disconnect: () => {
    const sock = get()._socket;
    if (sock) {
      sock.onclose = null;
      sock.close();
    }
    const timer = get()._reconnectTimer;
    if (timer) clearTimeout(timer);
    set({
      _socket: undefined,
      _reconnectTimer: undefined,
      status: "idle",
      _reconnectAttempts: 0,
    });
  },
}));

function scheduleReconnect(get: () => WSState) {
  const state = get();
  if (state._reconnectTimer) return;
  const attempt = state._reconnectAttempts + 1;
  const delay = Math.min(30_000, 1000 * Math.pow(2, Math.min(attempt, 5)));
  const timer = setTimeout(() => {
    useWSStore.setState({ _reconnectTimer: undefined });
    state.connect();
  }, delay);
  useWSStore.setState({
    _reconnectTimer: timer,
    _reconnectAttempts: attempt,
  });
}

/**
 * Select only the events relevant to a given scan instance.
 * Backend broadcasts events keyed to the subscribed instance, but dashboard
 * events have agent_id set to the originating scan when available.
 */
export function filterEventsForInstance(
  events: FeedEvent[],
  instanceId?: string,
): FeedEvent[] {
  if (!instanceId) return events;
  return events.filter((e) => {
    if (e.type === "instance_started" || e.type === "instance_updated") {
      return false;
    }
    if (e.instance_id) {
      return e.instance_id === instanceId;
    }
    if (e.agent_id) {
      return e.agent_id === instanceId;
    }
    return false;
  });
}
