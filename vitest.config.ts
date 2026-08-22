import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // `server-only` deliberately throws outside a React Server Component graph. Stub it
      // so the server modules can be unit-tested directly.
      "server-only": fileURLToPath(new URL("./tests/stubs/server-only.ts", import.meta.url)),
    },
  },
  test: {
    // Node 20+ exposes the same Web Crypto API the browser does, so the browser-side
    // crypto module runs unmodified here.
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Redis-backed suites share a keyspace; keep files sequential to avoid cross-talk.
    fileParallelism: false,
  },
});
