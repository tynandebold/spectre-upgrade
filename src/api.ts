import { invoke } from "@tauri-apps/api/core";

export interface SiteView {
  name: string;
  typeCode: number;
  loginType: number;
  counter: number;
  uses: number;
  lastUsed: string;
  url: string | null;
  stored: string | null;
  stateful: boolean;
  algorithm: number;
}

export interface Derived {
  password: string | null;
  login: string;
  answer: string;
}

export interface UnlockResult {
  siteCount: number;
  hasVault: boolean;
}

// Thin typed wrappers over the Rust commands. Tauri maps camelCase JS keys to
// the snake_case Rust parameters automatically.
export const api = {
  unlock: (fullName: string, masterPassword: string) =>
    invoke<UnlockResult>("unlock", { fullName, masterPassword }),

  lock: () => invoke<void>("lock"),

  listSites: () => invoke<SiteView[]>("list_sites"),

  derive: (name: string, counter: number, typeCode: number, loginType: number) =>
    invoke<Derived>("derive", { name, counter, typeCode, loginType }),

  copy: (text: string) => invoke<void>("copy", { text }),

  saveSite: (
    name: string,
    counter: number,
    typeCode: number,
    loginType: number,
    url: string | null,
    stored: string | null,
  ) => invoke<SiteView>("save_site", { name, counter, typeCode, loginType, url, stored }),

  recordUse: (name: string, nowIso: string) =>
    invoke<void>("record_use", { name, nowIso }),

  importVault: (path: string) => invoke<number>("import_vault", { path }),

  importFromApp: () => invoke<number>("import_from_app"),

  exportMpjson: (path: string, nowIso: string) =>
    invoke<number>("export_mpjson", { path, nowIso }),

  exportBackup: (path: string) => invoke<void>("export_backup", { path }),
};
