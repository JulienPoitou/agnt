import { useEffect, useState } from "react";
import Landing from "./components/Landing";
import Console from "./components/Console";

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

  return route.startsWith("/console") ? <Console /> : <Landing />;
}
