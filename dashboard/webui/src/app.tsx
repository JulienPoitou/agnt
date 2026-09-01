import { useEffect, type ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth, type AuthState } from "@/store/auth";
import { AppShell } from "@/layout/app-shell";
import { BackendUnreachable } from "@/pages/backend-unreachable";

export function AuthBootstrap({ children }: { children: ReactNode }) {
  const refresh = useAuth((s: AuthState) => s.refresh);
  const status = useAuth((s: AuthState) => s.status);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  if (status === "loading") {
    return (
      <div className="grid min-h-screen place-items-center bg-background">
        <div className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
          Loading…
        </div>
      </div>
    );
  }
  // When the API isn't reachable at all, render a remediation page in
  // place of every route — the login form would be misleading because
  // submitting it would just produce another 404. We render this above
  // the router so it covers /, /login, and every protected page alike.
  if (status === "no-backend") {
    return <BackendUnreachable />;
  }
  return <>{children}</>;
}

export function RequireAuth() {
  const status = useAuth((s: AuthState) => s.status);
  const location = useLocation();

  if (status === "anon") {
    return (
      <Navigate
        to="/login"
        state={{ from: location.pathname + location.search }}
        replace
      />
    );
  }
  return <AppShell />;
}

export function RedirectIfAuthed({ children }: { children: ReactNode }) {
  const status = useAuth((s: AuthState) => s.status);
  if (status === "authed" || status === "disabled") {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}
