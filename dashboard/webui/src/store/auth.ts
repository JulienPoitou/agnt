import { create } from "zustand"
import { api, AUTH_EXPIRED, HttpError } from "@/api/client"

// "no-backend" is distinct from "anon": it means the SPA could not even
// reach `/api/auth/status` (network error or 404). Without this state the
// app would silently render a login screen against an absent backend,
// which is exactly the bug behind the "HTTP 404 page not found" report.
type Status = "loading" | "anon" | "authed" | "disabled" | "no-backend"

export interface AuthState {
  status: Status
  // Whether the backend has auth configured. When `false`, requests still
  // succeed but we don't show login UI.
  authEnabled: boolean
  // Last error from the auth status probe, surfaced on the no-backend
  // page so operators can see "ECONNREFUSED" / "HTTP 404" verbatim.
  probeError: string | null
  refresh: () => Promise<void>
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const useAuth = create<AuthState>((set) => ({
  status: "loading",
  authEnabled: false,
  probeError: null,
  refresh: async () => {
    try {
      const res = await api.authStatus()
      if (!res.auth_enabled) {
        set({ status: "disabled", authEnabled: false, probeError: null })
        return
      }
      set({
        status: res.authenticated ? "authed" : "anon",
        authEnabled: true,
        probeError: null,
      })
    } catch (err) {
      // Network failure (status 0) or "endpoint missing" (404) means there
      // is no backend listening — showing the login form is misleading.
      // Anything else (500, 502, etc.) is a real backend that's misbehaving;
      // we still surface the login screen so the user can retry once the
      // server recovers.
      if (err instanceof HttpError && (err.status === 0 || err.status === 404)) {
        set({
          status: "no-backend",
          authEnabled: false,
          probeError: err.message,
        })
        return
      }
      set({
        status: "anon",
        authEnabled: true,
        probeError: err instanceof Error ? err.message : null,
      })
    }
  },
  login: async (username, password) => {
    await api.login(username, password)
    set({ status: "authed", authEnabled: true, probeError: null })
  },
  logout: async () => {
    try {
      await api.logout()
    } catch {
      /* ignore */
    }
    set({ status: "anon", authEnabled: true })
  },
}))

// Listen for global auth-expired events emitted by the API client whenever
// any request returns 401. Without this, an expired session would just
// surface as a generic toast on whichever screen the user happened to be
// on — they'd have to refresh manually to get the login form back.
if (typeof window !== "undefined") {
  window.addEventListener(AUTH_EXPIRED, () => {
    const { status, authEnabled } = useAuth.getState()
    // Only react if we currently think we're logged in. Avoids fighting
    // with the initial /api/auth/status probe when the app first loads.
    if (status === "authed" || authEnabled) {
      useAuth.setState({ status: "anon", authEnabled: true })
    }
  })
}
