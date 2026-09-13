import { useEffect, useMemo, useState, type FormEvent, type KeyboardEvent } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, type Derived, type SiteView } from "./api";

const PASSWORD_TYPES = [
  { code: 16, label: "Maximum" },
  { code: 17, label: "Long" },
  { code: 18, label: "Medium" },
  { code: 19, label: "Short" },
  { code: 20, label: "Basic" },
  { code: 21, label: "PIN" },
  { code: 31, label: "Phrase" },
  { code: 1056, label: "Own (saved)" },
];

function typeLabel(code: number): string {
  if (code >= 1024) {
    return "Own";
  }

  const match = PASSWORD_TYPES.find((t) => t.code === code);

  return match ? match.label : `Type ${code}`;
}

export default function App() {
  const [unlocked, setUnlocked] = useState(false);
  const [fullName, setFullName] = useState("Tynan Hall DeBold");
  const [masterPassword, setMasterPassword] = useState("");
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [sites, setSites] = useState<SiteView[]>([]);
  const [filter, setFilter] = useState("");
  const [sortMode, setSortMode] = useState<"alpha" | "recent">("alpha");
  const [selectedName, setSelectedName] = useState<string | null>(null);

  const [counter, setCounter] = useState(1);
  const [typeCode, setTypeCode] = useState(17);
  const [loginType, setLoginType] = useState(0);
  const [url, setUrl] = useState("");
  const [storedValue, setStoredValue] = useState("");

  const [derived, setDerived] = useState<Derived | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const selectedSite = useMemo(
    () => sites.find((s) => s.name === selectedName) ?? null,
    [sites, selectedName],
  );

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();

    if (!q) {
      return sites;
    }

    return sites.filter((s) => s.name.toLowerCase().includes(q));
  }, [sites, filter]);

  const displayed = useMemo(() => {
    if (sortMode === "alpha") {
      return filtered;
    }

    return [...filtered].sort(
      (a, b) =>
        (b.lastUsed || "").localeCompare(a.lastUsed || "") || a.name.localeCompare(b.name),
    );
  }, [filtered, sortMode]);

  const canAddNew =
    filter.trim().length > 0 &&
    !sites.some((s) => s.name.toLowerCase() === filter.trim().toLowerCase());

  const isStateful = typeCode >= 1024;

  const dirty = useMemo(() => {
    if (!selectedName) {
      return false;
    }

    if (!selectedSite) {
      return true;
    }

    return (
      counter !== selectedSite.counter ||
      typeCode !== selectedSite.typeCode ||
      loginType !== selectedSite.loginType ||
      (url || null) !== (selectedSite.url || null) ||
      (storedValue || null) !== (selectedSite.stored || null)
    );
  }, [selectedName, selectedSite, counter, typeCode, loginType, url, storedValue]);

  // Re-derive whenever the selection or its (possibly unsaved) settings change.
  useEffect(() => {
    if (!selectedName) {
      setDerived(null);

      return;
    }

    let cancelled = false;

    api
      .derive(selectedName, counter, typeCode, loginType)
      .then((d) => {
        if (!cancelled) {
          setDerived(d);
        }
      })
      .catch((e) => setStatus(String(e)));

    return () => {
      cancelled = true;
    };
  }, [selectedName, counter, typeCode, loginType]);

  // Auto-dismiss the status toast.
  useEffect(() => {
    if (!status) {
      return;
    }

    const timer = setTimeout(() => setStatus(null), 2000);

    return () => clearTimeout(timer);
  }, [status]);

  // Keep the keyboard-selected row visible.
  useEffect(() => {
    const el = document.querySelector(".list-item.selected");

    if (el) {
      el.scrollIntoView({ block: "nearest" });
    }
  }, [selectedName]);

  // Auto-lock after 5 minutes of inactivity.
  useEffect(() => {
    if (!unlocked) {
      return;
    }

    let timer: ReturnType<typeof setTimeout>;

    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(() => doLock(), 5 * 60 * 1000);
    };

    const events = ["mousemove", "keydown", "click"];

    events.forEach((e) => window.addEventListener(e, reset));
    reset();

    return () => {
      clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [unlocked]);

  async function doUnlock(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setUnlockError(null);

    try {
      await api.unlock(fullName, masterPassword);
      setMasterPassword("");
      setUnlocked(true);
      await refreshSites();
    } catch (err) {
      setUnlockError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function refreshSites() {
    const list = await api.listSites();

    setSites(list);
  }

  function selectSite(name: string, existing: SiteView | null) {
    setSelectedName(name);
    setCounter(existing?.counter ?? 1);
    setTypeCode(existing?.typeCode ?? 17);
    setLoginType(existing?.loginType ?? 0);
    setUrl(existing?.url ?? "");
    setStoredValue(existing?.stored ?? "");
    setStatus(null);
  }

  // One-click: selecting a site also copies its password (the common action).
  async function openAndCopy(name: string, existing: SiteView | null) {
    selectSite(name, existing);

    const c = existing?.counter ?? 1;
    const t = existing?.typeCode ?? 17;
    const l = existing?.loginType ?? 0;

    const d = await api.derive(name, c, t, l);

    if (d.password) {
      await api.copy(d.password);
      scheduleClipboardClear(d.password);
      setStatus(`Copied ${name} · clears in 30s`);
      await api.recordUse(name, new Date().toISOString());
      await refreshSites();
    }
  }

  // Clear the clipboard 30s after a copy (only if it still holds our value).
  function scheduleClipboardClear(text: string) {
    setTimeout(() => {
      api.clearClipboard(text).catch(() => {});
    }, 30000);
  }

  async function doCopy(label: string, text: string | null) {
    if (!text) {
      return;
    }

    await api.copy(text);
    scheduleClipboardClear(text);
    setStatus(`Copied ${label} · clears in 30s`);

    if (label === "password" && selectedName) {
      await api.recordUse(selectedName, new Date().toISOString());
      await refreshSites();
    }
  }

  async function doSave() {
    if (!selectedName) {
      return;
    }

    const saved = await api.saveSite(
      selectedName,
      counter,
      typeCode,
      loginType,
      url || null,
      isStateful ? storedValue || null : null,
    );

    setStatus("Saved");
    await refreshSites();
    setSelectedName(saved.name);
  }

  async function doImport() {
    const path = await open({
      multiple: false,
      filters: [{ name: "Spectre export", extensions: ["mpjson", "mpsites"] }],
    });

    if (typeof path !== "string") {
      return;
    }

    setBusy(true);

    try {
      const count = await api.importVault(path);

      setStatus(`Imported ${count} sites`);
      await refreshSites();
    } catch (err) {
      setStatus(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function doSyncFromApp() {
    setBusy(true);

    try {
      const count = await api.importFromApp();

      setStatus(`Synced ${count} sites from Spectre`);
      await refreshSites();
    } catch (err) {
      setStatus(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function doExportMpjson() {
    const path = await save({
      defaultPath: "spectre-export.mpjson",
      filters: [{ name: "Spectre export", extensions: ["mpjson"] }],
    });

    if (typeof path !== "string") {
      return;
    }

    const count = await api.exportMpjson(path, new Date().toISOString());

    setStatus(`Exported ${count} sites to .mpjson`);
  }

  async function doExportBackup() {
    const path = await save({
      defaultPath: "spectre-backup.spectre",
      filters: [{ name: "Encrypted backup", extensions: ["spectre"] }],
    });

    if (typeof path !== "string") {
      return;
    }

    await api.exportBackup(path);
    setStatus("Encrypted backup saved");
  }

  async function doLock() {
    await api.lock();
    setUnlocked(false);
    setSites([]);
    setSelectedName(null);
    setDerived(null);
  }

  // Keyboard-first navigation from the search box: arrows move the selection,
  // Enter copies the selected (or top) match, Escape clears the filter.
  function onSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (displayed.length === 0) {
      return;
    }

    const idx = displayed.findIndex((s) => s.name === selectedName);

    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = displayed[Math.min(displayed.length - 1, idx + 1)] ?? displayed[0];

      selectSite(next.name, next);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const prev = displayed[Math.max(0, idx - 1)] ?? displayed[0];

      selectSite(prev.name, prev);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const target = displayed[idx] ?? displayed[0];

      if (target) {
        openAndCopy(target.name, target);
      }
    } else if (e.key === "Escape") {
      setFilter("");
    }
  }

  if (!unlocked) {
    return (
      <div className="unlock">
        <form className="unlock-card" onSubmit={doUnlock}>
          <h1>Spectre Upgrade</h1>
          <label>
            Full name
            <input
              autoFocus
              onChange={(e) => setFullName(e.currentTarget.value)}
              value={fullName}
            />
          </label>
          <label>
            Master password
            <input
              onChange={(e) => setMasterPassword(e.currentTarget.value)}
              type="password"
              value={masterPassword}
            />
          </label>
          {unlockError && <p className="error">{unlockError}</p>}
          <button disabled={busy} type="submit">
            {busy ? "Unlocking…" : "Unlock"}
          </button>
          <p className="hint">
            Nothing is stored except your site list (encrypted). Your master
            password is never saved.
          </p>
        </form>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <input
          autoFocus
          className="search"
          onChange={(e) => setFilter(e.currentTarget.value)}
          onKeyDown={onSearchKeyDown}
          placeholder="Search or type a new site domain…"
          value={filter}
        />
        <div className="topbar-actions">
          <button disabled={busy} onClick={doSyncFromApp}>
            Sync from app
          </button>
          <button disabled={busy} onClick={doImport}>
            Import file…
          </button>
          <button onClick={doExportMpjson}>Export…</button>
          <button onClick={doExportBackup}>Backup…</button>
          <button onClick={doLock}>Lock</button>
        </div>
      </header>

      <div className="panes">
        <aside className="list">
          <div className="list-sort segmented">
            <button
              className={sortMode === "alpha" ? "active" : ""}
              onClick={() => setSortMode("alpha")}
            >
              A–Z
            </button>
            <button
              className={sortMode === "recent" ? "active" : ""}
              onClick={() => setSortMode("recent")}
            >
              Recent
            </button>
          </div>
          <div className="list-scroll">
            {canAddNew && (
              <button className="list-item add" onClick={() => selectSite(filter.trim(), null)}>
                + Use “{filter.trim()}”
              </button>
            )}
            {displayed.map((s) => (
              <button
                className={`list-item ${s.name === selectedName ? "selected" : ""}`}
                key={s.name}
                onClick={() => openAndCopy(s.name, s)}
              >
                <span className="site-name">{s.name}</span>
                <span className="site-meta">{typeLabel(s.typeCode)}</span>
              </button>
            ))}
          </div>
          <div className="list-footer">{sites.length} sites</div>
        </aside>

        <section className="detail">
          {!selectedName ? (
            sites.length === 0 ? (
              <div className="empty">
                <p>No sites yet.</p>
                <button disabled={busy} onClick={doSyncFromApp}>
                  Sync from Spectre app
                </button>
                <p className="hint">
                  Pulls your current site list straight from the Spectre app's
                  own data (no export needed).
                </p>
              </div>
            ) : (
              <div className="empty">Select a site, or type a domain to create one.</div>
            )
          ) : (
            <>
              <div className="detail-head">
                <h2>{selectedName}</h2>
                <span className="detail-sub">
                  {typeLabel(typeCode)} · v{selectedSite?.algorithm ?? 3}
                </span>
              </div>

              <div className="field">
                <div className="field-label">Password</div>
                {isStateful ? (
                  <div className="value-row">
                    <input
                      className="value big stored-input"
                      onChange={(e) => setStoredValue(e.currentTarget.value)}
                      placeholder="Paste your saved password for this site"
                      value={storedValue}
                    />
                    <button
                      disabled={!storedValue}
                      onClick={() => doCopy("password", storedValue || null)}
                    >
                      copy
                    </button>
                  </div>
                ) : (
                  <div className="value-row">
                    <code
                      className="value big"
                      onClick={() => doCopy("password", derived?.password ?? null)}
                      title="Click to copy"
                    >
                      {derived?.password ?? "…"}
                    </code>
                    <button
                      disabled={!derived?.password}
                      onClick={() => doCopy("password", derived?.password ?? null)}
                    >
                      copy
                    </button>
                  </div>
                )}
              </div>

              <div className="controls">
                {!isStateful && (
                  <div className="control">
                    <div className="field-label">Counter</div>
                    <div className="stepper">
                      <button onClick={() => setCounter((c) => Math.max(1, c - 1))}>–</button>
                      <span>{counter}</span>
                      <button onClick={() => setCounter((c) => c + 1)}>+</button>
                    </div>
                  </div>
                )}
                <div className="control">
                  <div className="field-label">Type</div>
                  <select
                    onChange={(e) => setTypeCode(Number(e.currentTarget.value))}
                    value={typeCode}
                  >
                    {PASSWORD_TYPES.map((t) => (
                      <option key={t.code} value={t.code}>
                        {t.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="field">
                <div className="field-label">Login name</div>
                <div className="value-row">
                  <code
                    className="value"
                    onClick={() => doCopy("login", derived?.login ?? null)}
                    title="Click to copy"
                  >
                    {derived?.login ?? "…"}
                  </code>
                  <button onClick={() => doCopy("login", derived?.login ?? null)}>copy</button>
                </div>
                <div className="toggle segmented">
                  <button className={loginType === 0 ? "active" : ""} onClick={() => setLoginType(0)}>
                    Standard
                  </button>
                  <button className={loginType !== 0 ? "active" : ""} onClick={() => setLoginType(30)}>
                    Generated
                  </button>
                </div>
              </div>

              <div className="field">
                <div className="field-label">Security answer (generic)</div>
                <div className="value-row">
                  <code
                    className="value"
                    onClick={() => doCopy("answer", derived?.answer ?? null)}
                    title="Click to copy"
                  >
                    {derived?.answer ?? "…"}
                  </code>
                  <button onClick={() => doCopy("answer", derived?.answer ?? null)}>copy</button>
                </div>
              </div>

              <div className="field">
                <div className="field-label">URL</div>
                <input
                  className="url-input"
                  onChange={(e) => setUrl(e.currentTarget.value)}
                  placeholder="eg. https://www.apple.com"
                  value={url}
                />
              </div>

              <div className="detail-foot">
                <div className="stats">
                  <span>uses {selectedSite?.uses ?? 0}</span>
                  <span>
                    {selectedSite?.lastUsed
                      ? `last used ${selectedSite.lastUsed.slice(0, 10)}`
                      : "never used"}
                  </span>
                </div>
                <button className="save" disabled={!dirty} onClick={doSave}>
                  {selectedSite ? "Save changes" : "Save site"}
                </button>
              </div>
            </>
          )}
          {status && <div className="status">{status}</div>}
        </section>
      </div>
    </div>
  );
}
