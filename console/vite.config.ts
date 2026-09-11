import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The built bundle is self-contained; the controller gateway can serve it, or host it standalone.
// In dev, /dani and /v1 proxy to a local controller gateway (override with DANI_GATEWAY).
const GATEWAY = process.env.DANI_GATEWAY ?? "http://127.0.0.1:8081";
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  server: {
    proxy: {
      "/dani": GATEWAY,
      "/v1": GATEWAY,
    },
  },
  build: { outDir: "dist" },
});
