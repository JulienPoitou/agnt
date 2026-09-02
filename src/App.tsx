import { useEffect, useState } from "react";
import Landing from "./components/Landing";
import Console from "./components/Console";
import WebScan from "./components/WebScan";

function currentRoute(): string {
  const h = window.location.hash.replace(/^#/, "");
  return h === "" ? "/" : h;
}

export default function App() {
  const [route, setRoute] = useState(currentRoute);

  useEffect(() => {
    const onHash = () => setRoute(currentRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return (
    <div key={route} className="route-swap">
      {route.startsWith("/console") ? <Console />
       : route.startsWith("/web") ? <WebScan />
       : <Landing />}
    </div>
  );
}
