import { CAPTURES } from "@/lib/api";

import { MissionWorkspace } from "./_components/mission-workspace";
import { resolveView } from "./_components/capture-notes";

export default async function Page({
  searchParams,
}: Readonly<{ searchParams: Promise<Record<string, string | string[] | undefined>> }>) {
  const raw = await searchParams;
  const key = typeof raw.v === "string" ? raw.v : undefined;
  const active = resolveView(key, CAPTURES);
  return <MissionWorkspace captures={CAPTURES} active={active} />;
}
