/// <reference types="svelte" />
/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly TERRALIST_VERSION: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
