import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  test: {
    env: {
      VITE_SUPABASE_URL: "https://your-supabase-url.com",
      VITE_SUPABASE_ANON_KEY: "your-supabase-anon-key",
    },
  },
  plugins: [react()],
  optimizeDeps: {
    exclude: ["lucide-react"],
  },
});
