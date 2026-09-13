import { useEffect, useMemo, useState, type FormEvent } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type Derived, type SiteView } from "./api";

const PASSWORD_TYPES = [
  { code: 16, label: "Maximum" },
  { code: 17, label: "Long" },
  { code: 18, label: "Medium" },
  { code: 19, label: "Short" },
  { code: 20, label: "Basic" },
  { code: 21, label: "PIN" },
  { code: 31, label: "Phrase" },
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
  const [selectedName, setSelectedName] = useState<string | null>(null);

  const [counter, setCounter] = useState(1);
  const [typeCode, setTypeCode] = useState(17);
  const [loginType, setLoginType] = useState(0);
  const [url, setUrl] = useState("");

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
      (url || null) !== (selectedSite.url || null)
    );
  }, [selectedName, selectedSite, counter, typeCode, loginType, url]);

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
    setStatus(null);
  }

  async function doCopy(label: string, text: string | null) {
    if (!text) {
      return;
    }

    await api.copy(text);
    setStatus(`Copied ${label}`);

    if (label === "password" && selectedName) {
      await api.recordUse(selectedName, new Date().toISOString());
      await refreshSites();
    }
  }

  async function doSave() {
    if (!selectedName) {
      return;
    }

    const saved = await api.saveSite(selectedName, counter, typeCode, loginType, url || null);

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

  async function doLock() {
    await api.lock();
    setUnlocked(false);
    setSites([]);
    setSelectedName(null);
    setDerived(null);
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
          className="search"
          onChange={(e) => setFilter(e.currentTarget.value)}
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
          <button onClick={doLock}>Lock</button>
        </div>
      </header>

      <div className="panes">
        <aside className="list">
          {canAddNew && (
            <button className="list-item add" onClick={() => selectSite(filter.trim(), null)}>
              + Use “{filter.trim()}”
            </button>
          )}
          {filtered.map((s) => (
            <button
              className={`list-item ${s.name === selectedName ? "selected" : ""}`}
              key={s.name}
              onClick={() => selectSite(s.name, s)}
            >
              <span className="site-name">{s.name}</span>
              <span className="site-meta">{typeLabel(s.typeCode)}</span>
            </button>
          ))}
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
                <div className="value-row">
                  <code className="value big">
                    {isStateful
                      ? derived?.password ?? "— stored in original app —"
                      : derived?.password ?? "…"}
                  </code>
                  <button
                    disabled={!derived?.password}
                    onClick={() => doCopy("password", derived?.password ?? null)}
                  >
                    copy
                  </button>
                </div>
              </div>

              {!isStateful && (
                <div className="controls">
                  <div className="control">
                    <div className="field-label">Counter</div>
                    <div className="stepper">
                      <button onClick={() => setCounter((c) => Math.max(1, c - 1))}>–</button>
                      <span>{counter}</span>
                      <button onClick={() => setCounter((c) => c + 1)}>+</button>
                    </div>
                  </div>
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
              )}

              <div className="field">
                <div className="field-label">Login name</div>
                <div className="value-row">
                  <code className="value">{derived?.login ?? "…"}</code>
                  <button onClick={() => doCopy("login", derived?.login ?? null)}>copy</button>
                </div>
                <div className="toggle">
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
                  <code className="value">{derived?.answer ?? "…"}</code>
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
