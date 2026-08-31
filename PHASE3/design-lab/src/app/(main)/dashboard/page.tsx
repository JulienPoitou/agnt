import { getHistory, getDetail } from "@/lib/api";
import { MissionWorkspace } from "./_components/mission-workspace";
export default async function Page(){ return <MissionWorkspace history={await getHistory()} detail={await getDetail()} />; }
