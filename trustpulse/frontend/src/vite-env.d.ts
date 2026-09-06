/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_TRUSTPULSE_API_KEY?: string;
  readonly VITE_TRUSTPULSE_TENANT?: string;
  readonly VITE_PROXY_TARGET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
