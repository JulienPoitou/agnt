import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Freebuff exige HMR désactivé — ne pas modifier.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    hmr: false,
    // En local on passe par localhost ; dans un bac à sable de preview l'hôte
    // est un sous-domaine proxy — on l'autorise pour que la page se charge.
    allowedHosts: true,
    port: Number(process.env.PORT) || 5173,
    // La console React parle à la VRAIE API moteur (PHASE3/interface/api.py,
    // port 8141). En dev on proxifie /api → pas de CORS, mêmes origines.
    // Si l'API est éteinte, le fetch échoue et l'écran retombe sur le rejeu,
    // affiché comme rejeu (jamais comme un résultat réel).
    proxy: {
      "/api": {
        target: process.env.AGNT_API || "http://127.0.0.1:8141",
        changeOrigin: true,
      },
    },
  },
  preview: {
    host: "0.0.0.0",
    port: Number(process.env.PORT) || 5173,
    proxy: {
      "/api": {
        target: process.env.AGNT_API || "http://127.0.0.1:8141",
        changeOrigin: true,
      },
    },
  },
});
