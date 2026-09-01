import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useI18n } from "@/i18n";

/**
 * Page Capacités — ce que le moteur AGNT sait FAIRE, lu en direct dans le
 * registre (`GET /api/capacites`) : capacités publiées, providers, moteurs,
 * confiances, profil d'exécution. Rien n'est codé en dur ici : si le registre
 * change (nouveau provider qualifié), la page change avec lui.
 */
export default function CapacitesPage() {
  const { t } = useI18n();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["capacites"],
    queryFn: api.capacites,
    refetchInterval: 30_000,
  });

  const caps = data?.capacites ?? [];
  const providers = data?.providers ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("nav.capacites")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Registre du moteur AGNT — capacités publiées et providers qualifiés.
          Lecture directe, rien n'est ajouté ici.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Metric label="Capacités" value={caps.length} />
        <Metric label="Providers" value={providers.length} />
        <Metric label="Confiances" value={data?.confiances?.length ?? 0} />
      </div>

      {isError && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Registre injoignable — le moteur est-il démarré ?
          </CardContent>
        </Card>
      )}

      {isLoading && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Chargement du registre…
          </CardContent>
        </Card>
      )}

      {!isLoading && !isError && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Capacités publiées</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {caps.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  Aucune capacité publiée — {data?.registre_erreur ?? "registre vide"}
                </p>
              )}
              {caps.map((c) => (
                <div
                  key={c.id}
                  className="rounded-md border border-border bg-background/50 p-3"
                >
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="mono text-[10px]">
                      {c.id}
                    </Badge>
                  </div>
                  {c.description && (
                    <p className="mt-1.5 text-xs text-muted-foreground">
                      {c.description}
                    </p>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Providers qualifiés</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-1.5">
              {providers.map((p) => (
                <Badge key={p} variant="outline" className="mono text-[10px]">
                  {p}
                </Badge>
              ))}
              {providers.length === 0 && (
                <p className="text-sm text-muted-foreground">Aucun provider publié.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Moteurs &amp; profil</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs">
              <Row label="Moteurs d'intention" value={(data?.moteurs ?? []).join(", ")} />
              <Row label="Confiances admises" value={(data?.confiances ?? []).join(", ")} />
              <Row
                label="Profil d'exécution"
                value={
                  data?.profil && "nom" in data.profil
                    ? String(data.profil.nom)
                    : "—"
                }
              />
              <Row
                label="Réseau du profil"
                value={
                  data?.profil && "reseau_autorise" in data.profil
                    ? String(data.profil.reseau_autorise)
                    : "—"
                }
              />
              <Row
                label="LLM"
                value={
                  data?.llm && "fournisseur" in data.llm
                    ? `${String(data.llm.fournisseur)} · clé ${
                        data.llm.cle_presente ? "présente" : "absente"
                      }`
                    : "—"
                }
              />
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardContent className="py-4">
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        <div className="mt-0.5 text-xs text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border/60 pb-1.5 last:border-0">
      <span className="text-muted-foreground">{label}</span>
      <span className="mono">{value || "—"}</span>
    </div>
  );
}
