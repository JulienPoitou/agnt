import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Freebuff exige HMR désactivé — ne pas modifier.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    hmr: false,
    port: Number(process.env.PORT) || 8141,
  },
  preview: {
    host: "0.0.0.0",
    port: Number(process.env.PORT) || 8141,
  },
});
