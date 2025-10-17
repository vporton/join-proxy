import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import { InternetIdentityProvider } from 'ic-use-internet-identity'

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <InternetIdentityProvider loginOptions={{
      identityProvider: import.meta.env.DFX_NETWORK === "local"
        ? `http://${import.meta.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:8080`
        : "https://identity.ic0.app"
    }}>
      <App />
    </InternetIdentityProvider>
  </StrictMode>
);
