import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import environment from 'vite-plugin-environment';
import dotenv from 'dotenv';

dotenv.config({ path: '../../.env' });

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    environment("all", { prefix: "CANISTER_", defineOn: 'import.meta.env' }),
    environment("all", { prefix: "DFX_", defineOn: 'import.meta.env' }),
    // environment("all", { prefix: "CANISTER_", defineOn: 'process.env' }),
    environment("all", { prefix: "DFX_", defineOn: 'process.env' }), // `process.env` for `ic-use-internet-identity`
  ],
})
