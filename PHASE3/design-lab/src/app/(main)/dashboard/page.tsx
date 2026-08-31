import { getDetail, getHistory } from "@/lib/api";

import { MissionWorkspace } from "./_components/mission-workspace";

export default async function Page() {
  const history = getHistory();
  const first = history.items[0];
  if (!first) throw new Error("la capture « list » ne contient aucune mission");
  const detail = getDetail(first.mission_id);
  if (!detail) throw new Error(`détail capturé absent pour ${first.mission_id}`);
  return <MissionWorkspace history={history} detail={detail} />;
}
