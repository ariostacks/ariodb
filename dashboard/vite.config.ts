import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// The built files are embedded in the ariodb binary (see src/dashboard.rs),
// so the output goes to dist/ with hashed names under /assets/.
// `npm run dev` proxies the JSON API to a locally running ariodb.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "assets",
    // No source maps in the shipped binary.
    sourcemap: false,
    // One bundle is fine for a dashboard served from the same binary;
    // React itself is most of it.
    chunkSizeWarningLimit: 700,
  },
  server: {
    proxy: {
      "/api": process.env.ARIODB_DASHBOARD ?? "http://127.0.0.1:8080",
    },
  },
})
