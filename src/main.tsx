import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Archive,
  BadgeCheck,
  Clipboard,
  Database,
  Edit3,
  Eye,
  FileDown,
  FileKey2,
  FilePlus2,
  Folder,
  FolderLock,
  Globe,
  KeyRound,
  LockKeyhole,
  LogOut,
  Plus,
  RefreshCw,
  Save,
  Search,
  Settings,
  ShieldCheck,
  Shuffle,
  Trash2,
  User,
  UserCog,
  Users,
  WandSparkles
} from "lucide-react";
import { api } from "./api/client";
import { generatePassword as generateCredentialPassword } from "./lib/passwordGenerator";
import type { AccessRequest, AddSecret, AuditEvent, ConsoleData, Policies, Secret, UserRecord } from "./types";
import "./styles.css";

const blankSecret = (vaultId = ""): AddSecret => ({
  vaultId,
  type: "password",
  name: "",
  username: "",
  password: "",
  repeat: "",
  url: "",
  tags: "",
  notes: ""
});

function Login({ onLogin }: { onLogin: (token: string, data: ConsoleData) => void }) {
  const [email, setEmail] = useState("ada@defence.local");
  const [password, setPassword] = useState("Passw0rd!");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const login = await api<{ token: string; user: UserRecord }>("/api/login", { method: "POST", body: JSON.stringify({ email, password }) });
      const data = await api<ConsoleData>("/api/console", {}, login.token);
      onLogin(login.token, data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to sign in");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login-shell">
      <section className="unlock-card" aria-label="Open database">
        <div className="app-badge">
          <FileKey2 size={26} />
          <span>Sentinel.kdbx</span>
        </div>
        <h1>Open enterprise password database</h1>
        <p>Unlock the multi-user vault workbench with a defence identity and MFA-backed session.</p>
        <form onSubmit={submit} className="unlock-form">
          <label>
            User name
            <input value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" />
          </label>
          <label>
            Master key
            <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" />
          </label>
          {error && <div className="error">{error}</div>}
          <button className="primary" disabled={busy}><LockKeyhole size={17} />{busy ? "Opening..." : "Open Database"}</button>
        </form>
        <div className="demo-accounts">
          <span>Demo identities</span>
          <button type="button" onClick={() => setEmail("ada@defence.local")}>Security Admin</button>
          <button type="button" onClick={() => setEmail("morgan@defence.local")}>Vault Operator</button>
          <button type="button" onClick={() => setEmail("iris@defence.local")}>Auditor</button>
          <small>Password: Passw0rd!</small>
        </div>
      </section>
    </main>
  );
}

function App() {
  const [token, setToken] = useState(() => localStorage.getItem("sentinel-token") || "");
  const [data, setData] = useState<ConsoleData | null>(null);
  const [selectedGroup, setSelectedGroup] = useState("all");
  const [selectedSecretId, setSelectedSecretId] = useState("");
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<"entries" | "access" | "audit" | "users" | "policy" | "manage">("entries");
  const [reveal, setReveal] = useState<{ name: string; password: string; expiresIn: number } | null>(null);
  const [toast, setToast] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [locked, setLocked] = useState(false);
  const [addSecret, setAddSecret] = useState<AddSecret>(blankSecret());
  const [generator, setGenerator] = useState({ length: 24, upper: true, lower: true, digits: true, symbols: true, noAmbiguous: true });

  const load = async (activeToken = token) => {
    if (!activeToken) return;
    const fresh = await api<ConsoleData>("/api/console", {}, activeToken);
    setData(fresh);
    const firstVault = fresh.vaults[0]?.id || "";
    setAddSecret((current) => ({ ...current, vaultId: current.vaultId || firstVault }));
    if (!selectedSecretId && fresh.secrets[0]) setSelectedSecretId(fresh.secrets[0].id);
  };

  useEffect(() => {
    load().catch(() => {
      localStorage.removeItem("sentinel-token");
      setToken("");
    });
  }, []);

  const onLogin = (nextToken: string, nextData: ConsoleData) => {
    localStorage.setItem("sentinel-token", nextToken);
    setToken(nextToken);
    setData(nextData);
    setSelectedGroup("all");
    setSelectedSecretId(nextData.secrets[0]?.id || "");
    setAddSecret(blankSecret(nextData.vaults[0]?.id || ""));
  };

  const signOut = () => {
    localStorage.removeItem("sentinel-token");
    setToken("");
    setData(null);
  };

  const action = async (work: () => Promise<void>, message: string) => {
    try {
      await work();
      await load();
      setToast(message);
      window.setTimeout(() => setToast(""), 2400);
    } catch (err) {
      setToast(err instanceof Error ? err.message : "Action failed");
    }
  };

  const generatePassword = () => {
    const password = generateCredentialPassword(generator);
    setAddSecret((current) => ({ ...current, password, repeat: password }));
  };

  if (!data || !token) return <Login onLogin={onLogin} />;

  const can = (permission: string) => data.user.permissions.includes(permission);
  const groupCounts = new Map<string, number>();
  data.secrets.forEach((secret) => groupCounts.set(secret.vaultId, (groupCounts.get(secret.vaultId) || 0) + 1));

  const filteredSecrets = data.secrets.filter((secret) => {
    const groupMatch = selectedGroup === "all" || selectedGroup === secret.vaultId || (selectedGroup === "shared" && secret.sharedWith.length > 1) || (selectedGroup === "risk" && secret.risk === "high");
    const text = [secret.name, secret.username, secret.url, secret.tags.join(" ")].join(" ").toLowerCase();
    return groupMatch && text.includes(query.toLowerCase());
  });
  const selectedSecret = data.secrets.find((secret) => secret.id === selectedSecretId) || filteredSecrets[0] || data.secrets[0];
  const selectedVault = data.vaults.find((vault) => vault.id === selectedSecret?.vaultId);

  const submitSecret = (event: React.FormEvent) => {
    event.preventDefault();
    if (addSecret.password !== addSecret.repeat) {
      setToast("Password and repeat fields do not match");
      return;
    }
    action(async () => {
      await api("/api/secrets", { method: "POST", body: JSON.stringify(addSecret) }, token);
      setAddOpen(false);
      setAddSecret(blankSecret(data.vaults[0]?.id || ""));
    }, "Entry added to database");
  };

  const revealSecret = (secret: Secret) => {
    action(async () => {
      const result = await api<{ password: string; expiresIn: number }>(`/api/secrets/${secret.id}/reveal`, { method: "POST" }, token);
      setReveal({ name: secret.name, ...result });
    }, "Password field revealed");
  };

  const copyUsername = (secret: Secret) => {
    navigator.clipboard.writeText(secret.username);
    setToast(`Copied user name for ${secret.name}`);
  };

  const updatePolicy = (patch: Partial<Policies>) => {
    action(async () => {
      await api("/api/policies", { method: "PATCH", body: JSON.stringify(patch) }, token);
    }, "Policy updated");
  };

  const decideAccessRequest = (request: AccessRequest, decision: "approve" | "deny") => {
    action(async () => {
      await api(`/api/access-requests/${request.id}/${decision}`, { method: "POST", body: JSON.stringify({ minutes: 30 }) }, token);
    }, decision === "approve" ? "Temporary access approved" : "Temporary access denied");
  };

  return (
    <main className={`window-shell ${locked ? "is-locked" : ""}`}>
      <section className="titlebar">
        <div><FileKey2 size={17} />Sentinel.kdbx - Sentinel Vault Enterprise</div>
        <div className="window-controls"><span /><span /><span /></div>
      </section>

      <section className="menubar">
        {["File", "Edit", "View", "Entry", "Tools", "Help"].map((item) => <button key={item}>{item}</button>)}
        <span className="session-label"><BadgeCheck size={15} />{data.user.name} · {data.user.role.replace("_", " ")}</span>
      </section>

      <section className="toolbar">
        <button title="New database"><Database size={18} /></button>
        <button title="Save database"><Save size={18} /></button>
        <button title="Add entry" disabled={!can("vault:write")} onClick={() => setAddOpen(true)}><FilePlus2 size={18} /></button>
        <button title="Edit selected entry" disabled={!selectedSecret}><Edit3 size={18} /></button>
        <button title="Delete selected entry" disabled><Trash2 size={18} /></button>
        <span className="divider" />
        <button title="Copy user name" disabled={!selectedSecret} onClick={() => selectedSecret && copyUsername(selectedSecret)}><User size={18} /></button>
        <button title="Reveal password" disabled={!selectedSecret} onClick={() => selectedSecret && revealSecret(selectedSecret)}><KeyRound size={18} /></button>
        <button title="Rotate password" disabled={!selectedSecret || !can("vault:write")} onClick={() => selectedSecret && action(async () => { await api(`/api/secrets/${selectedSecret.id}/rotate`, { method: "POST" }, token); }, "Entry password rotated")}><RefreshCw size={18} /></button>
        <button title="Share entry" disabled={!selectedSecret || !can("vault:share")} onClick={() => selectedSecret && action(async () => { await api(`/api/secrets/${selectedSecret.id}/share`, { method: "POST", body: JSON.stringify({ userId: "u3" }) }, token); }, "Entry shared with auditor")}><UserCog size={18} /></button>
        <span className="divider" />
        <button title="Lock workspace" onClick={() => setLocked(true)}><LockKeyhole size={18} /></button>
        <button title="Sign out" onClick={signOut}><LogOut size={18} /></button>
        <label className="quick-search">
          <Search size={16} />
          <input placeholder="Search..." value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
      </section>

      <section className="database-tabs">
        <button className="active"><Database size={15} />Sentinel.kdbx</button>
        <button><Archive size={15} />BreakGlass.kdbx</button>
      </section>

      <section className="workbench">
        <aside className="group-tree">
          <TreeButton active={selectedGroup === "all"} icon={<FolderLock />} label="Database" meta={`${data.secrets.length} entries`} onClick={() => setSelectedGroup("all")} />
          {data.vaults.map((vault) => (
            <TreeButton key={vault.id} active={selectedGroup === vault.id} icon={<Folder />} label={vault.name} meta={`${groupCounts.get(vault.id) || 0} entries`} onClick={() => setSelectedGroup(vault.id)} inset />
          ))}
          <TreeButton active={selectedGroup === "shared"} icon={<Users />} label="Shared Entries" meta="delegated" onClick={() => setSelectedGroup("shared")} />
          <TreeButton active={selectedGroup === "risk"} icon={<ShieldCheck />} label="High Risk" meta={`${data.metrics.highRisk} flagged`} onClick={() => setSelectedGroup("risk")} />
          <div className="tree-footer">
            <strong>{data.metrics.pendingRequests}</strong>
            <span>Pending access requests</span>
          </div>
        </aside>

        <section className="entry-pane">
          <div className="view-tabs">
            <button className={tab === "entries" ? "active" : ""} onClick={() => setTab("entries")}>Entries</button>
            <button className={tab === "access" ? "active" : ""} onClick={() => setTab("access")}>Access</button>
            <button className={tab === "audit" ? "active" : ""} onClick={() => setTab("audit")}>Audit</button>
            <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}>Users</button>
            <button className={tab === "policy" ? "active" : ""} onClick={() => setTab("policy")}>Options</button>
            <button className={tab === "manage" ? "active" : ""} onClick={() => setTab("manage")}>Manage</button>
          </div>

          {tab === "entries" && (
            <>
              <div className="entry-table" role="table" aria-label="Password entries">
                <div className="table-header" role="row">
                  <span>Title</span><span>User Name</span><span>Password</span><span>URL</span><span>Modified</span><span>Quality</span>
                </div>
                {filteredSecrets.map((secret) => (
                  <button className={`entry-row ${selectedSecret?.id === secret.id ? "selected" : ""}`} key={secret.id} onClick={() => setSelectedSecretId(secret.id)} role="row">
                    <span><Globe size={16} />{secret.name}<small>{secret.type.replace("_", " ")}</small></span>
                    <span>{secret.username}</span>
                    <span>••••••••••••</span>
                    <span>{secret.url}</span>
                    <span>{new Date(secret.rotatedAt).toLocaleDateString()}</span>
                    <span><meter min={0} max={100} value={secret.strength} />{secret.strength}%</span>
                  </button>
                ))}
              </div>

              {selectedSecret && (
                <section className="details-pane">
                  <div>
                    <h2>{selectedSecret.name}</h2>
                    <p>{selectedVault?.name} · {selectedVault?.classification} · {selectedSecret.tags.join(", ") || "No tags"}</p>
                  </div>
                  <div className="detail-actions">
                    <button onClick={() => copyUsername(selectedSecret)}><Clipboard size={16} />Copy User</button>
                    <button onClick={() => revealSecret(selectedSecret)}><Eye size={16} />Reveal</button>
                    <button disabled={!can("vault:write")} onClick={() => action(async () => { await api(`/api/secrets/${selectedSecret.id}/rotate`, { method: "POST" }, token); }, "Entry password rotated")}><Shuffle size={16} />Rotate</button>
                  </div>
                  <dl>
                    <div><dt>User Name</dt><dd>{selectedSecret.username}</dd></div>
                    <div><dt>Type</dt><dd>{selectedSecret.type.replace("_", " ")}</dd></div>
                    <div><dt>URL</dt><dd>{selectedSecret.url}</dd></div>
                    <div><dt>Risk</dt><dd className={`risk ${selectedSecret.risk}`}>{selectedSecret.risk}</dd></div>
                    <div><dt>Approval</dt><dd>{selectedSecret.approvalsRequired ? "Required" : "Standard"}</dd></div>
                    <div><dt>Shared With</dt><dd>{selectedSecret.sharedWith.length} identities</dd></div>
                  </dl>
                  <textarea value={`${selectedSecret.notes || "Entry notes"}\nOwner unit: ${selectedVault?.ownerUnit || "Unknown"}\nRotation policy: ${data.policies.rotationDays} days\nLast modified: ${new Date(selectedSecret.rotatedAt).toLocaleString()}`} readOnly />
                </section>
              )}
            </>
          )}

          {tab === "access" && <AccessTable requests={data.accessRequests} canApprove={can("vault:share")} onDecision={decideAccessRequest} />}
          {tab === "audit" && <AuditTable events={data.audit} />}
          {tab === "users" && <UserTable users={data.users} />}
          {tab === "policy" && <PolicyPanel policies={data.policies} canWrite={can("policy:write")} onChange={updatePolicy} />}
          {tab === "manage" && <ManagementPanel data={data} />}
        </section>
      </section>

      <section className="statusbar">
        <span>{data.vaults.length} groups / {filteredSecrets.length} entries</span>
        <span>{selectedSecret ? `1 of ${filteredSecrets.length} selected` : "No entry selected"}</span>
        <span>{data.identity.name} / SIEM {data.integrations.siem.mode}</span>
      </section>

      {locked && (
        <div className="lock-overlay">
          <div>
            <LockKeyhole size={42} />
            <h2>Workspace Locked</h2>
            <p>Sentinel.kdbx is locked. Unlock to continue the active session.</p>
            <button className="primary" onClick={() => setLocked(false)}>Unlock Workspace</button>
          </div>
        </div>
      )}

      {addOpen && (
        <div className="modal-backdrop" onClick={() => setAddOpen(false)}>
          <dialog open className="entry-dialog" onClick={(event) => event.stopPropagation()}>
            <header>
              <FilePlus2 size={28} />
              <div><h2>Add Entry</h2><p>Create a new credential record.</p></div>
            </header>
            <form onSubmit={submitSecret}>
              <div className="dialog-tabs"><span className="active">Entry</span><span>Advanced</span><span>Auto-Type</span><span>History</span></div>
              <label>Group<select value={addSecret.vaultId} onChange={(event) => setAddSecret({ ...addSecret, vaultId: event.target.value })}>{data.vaults.map((vault) => <option value={vault.id} key={vault.id}>{vault.name}</option>)}</select></label>
              <label>Secret type<select value={addSecret.type} onChange={(event) => setAddSecret({ ...addSecret, type: event.target.value })}>
                <option value="password">Password</option>
                <option value="api_key">API key</option>
                <option value="ssh_key">SSH key</option>
                <option value="certificate">Certificate</option>
                <option value="token">Token</option>
                <option value="connection_string">Connection string</option>
              </select></label>
              <label>Title<input value={addSecret.name} onChange={(event) => setAddSecret({ ...addSecret, name: event.target.value })} /></label>
              <label>User name<input value={addSecret.username} onChange={(event) => setAddSecret({ ...addSecret, username: event.target.value })} /></label>
              <label>Password<div className="password-line"><input value={addSecret.password} onChange={(event) => setAddSecret({ ...addSecret, password: event.target.value })} /><button type="button" onClick={generatePassword}><WandSparkles size={16} /></button></div></label>
              <label>Repeat<input value={addSecret.repeat} onChange={(event) => setAddSecret({ ...addSecret, repeat: event.target.value })} /></label>
              <div className="quality-line"><meter min={0} max={100} value={Math.min(100, addSecret.password.length * 4.6)} /><span>{Math.round(Math.min(100, addSecret.password.length * 4.6))}% quality</span></div>
              <label>URL<input value={addSecret.url} onChange={(event) => setAddSecret({ ...addSecret, url: event.target.value })} /></label>
              <label>Tags<input value={addSecret.tags} onChange={(event) => setAddSecret({ ...addSecret, tags: event.target.value })} /></label>
              <label>Notes<textarea value={addSecret.notes} onChange={(event) => setAddSecret({ ...addSecret, notes: event.target.value })} /></label>
              <fieldset className="generator-box">
                <legend>Password Generator</legend>
                <label>Length<input type="number" min={12} max={64} value={generator.length} onChange={(event) => setGenerator({ ...generator, length: Number(event.target.value) })} /></label>
                <label><input type="checkbox" checked={generator.upper} onChange={(event) => setGenerator({ ...generator, upper: event.target.checked })} />Uppercase</label>
                <label><input type="checkbox" checked={generator.lower} onChange={(event) => setGenerator({ ...generator, lower: event.target.checked })} />Lowercase</label>
                <label><input type="checkbox" checked={generator.digits} onChange={(event) => setGenerator({ ...generator, digits: event.target.checked })} />Digits</label>
                <label><input type="checkbox" checked={generator.symbols} onChange={(event) => setGenerator({ ...generator, symbols: event.target.checked })} />Symbols</label>
              </fieldset>
              <footer>
                <button type="button" className="secondary" onClick={() => setAddOpen(false)}>Cancel</button>
                <button className="primary" disabled={!can("vault:write")}>OK</button>
              </footer>
            </form>
          </dialog>
        </div>
      )}

      {reveal && (
        <div className="modal-backdrop" onClick={() => setReveal(null)}>
          <dialog open onClick={(event) => event.stopPropagation()}>
            <h2>{reveal.name}</h2>
            <p>Visible for {reveal.expiresIn} seconds under active audit.</p>
            <code>{reveal.password}</code>
            <button className="secondary" onClick={() => navigator.clipboard.writeText(reveal.password)}><Clipboard size={16} />Copy Password</button>
          </dialog>
        </div>
      )}

      {toast && <div className="toast">{toast}</div>}
    </main>
  );
}

function TreeButton({ active, icon, label, meta, onClick, inset = false }: { active: boolean; icon: React.ReactNode; label: string; meta: string; onClick: () => void; inset?: boolean }) {
  return <button className={`tree-button ${active ? "active" : ""} ${inset ? "inset" : ""}`} onClick={onClick}>{icon}<span>{label}</span><small>{meta}</small></button>;
}

function AccessTable({ requests, canApprove, onDecision }: { requests: AccessRequest[]; canApprove: boolean; onDecision: (request: AccessRequest, decision: "approve" | "deny") => void }) {
  return (
    <div className="utility-table">
      <div className="table-header access"><span>Requested</span><span>Secret</span><span>Requester</span><span>Status</span><span>Decision</span></div>
      {requests.map((request) => (
        <div className="access-line" key={request.id}>
          <span>{new Date(request.requestedAt).toLocaleString()}</span>
          <strong>{request.secretName}</strong>
          <span>{request.requesterName}</span>
          <span>{request.status} {request.approvalCount}/{request.requiredApprovals}{request.expiresAt ? ` until ${new Date(request.expiresAt).toLocaleTimeString()}` : ""}</span>
          <small>
            {request.ticketRef ? `${request.ticketRef} - ` : ""}{request.reason}
            {canApprove && request.status === "pending" && (
              <span className="row-actions">
                <button onClick={() => onDecision(request, "approve")}>Approve</button>
                <button onClick={() => onDecision(request, "deny")}>Deny</button>
              </span>
            )}
          </small>
        </div>
      ))}
    </div>
  );
}

function AuditTable({ events }: { events: AuditEvent[] }) {
  return (
    <div className="utility-table">
      <div className="table-header audit"><span>Time</span><span>Action</span><span>Actor</span><span>Target</span><span>Detail</span></div>
      {events.map((event) => <div className="audit-line" key={event.id}><span>{new Date(event.ts).toLocaleString()}</span><strong>{event.action}</strong><span>{event.actor}</span><span>{event.target}</span><small>{event.detail}</small></div>)}
    </div>
  );
}

function UserTable({ users }: { users: UserRecord[] }) {
  return (
    <div className="utility-table">
      <div className="table-header users"><span>Name</span><span>Email</span><span>Role</span><span>MFA</span><span>Unit</span></div>
      {users.map((user) => <div className="user-line" key={user.id}><strong>{user.name}</strong><span>{user.email}</span><span>{user.role.replace("_", " ")}</span><span>{user.mfa ? "Enabled" : "Disabled"}</span><span>{user.unit}</span></div>)}
    </div>
  );
}

function ManagementPanel({ data }: { data: ConsoleData }) {
  return (
    <div className="options-panel management-panel">
      <h2><Settings size={18} />Management</h2>
      <dl>
        <div><dt>Identity</dt><dd>{data.identity.name} ({data.identity.mode})</dd></div>
        <div><dt>Crypto</dt><dd>{data.crypto.algorithm} / {data.crypto.keyVersion}</dd></div>
        <div><dt>Storage</dt><dd>{data.storage.mode} v{data.storage.stateVersion}</dd></div>
        <div><dt>Backups</dt><dd>{data.storage.backups.length} retained</dd></div>
        <div><dt>SIEM</dt><dd>{data.integrations.siem.mode}</dd></div>
        <div><dt>DevOps tokens</dt><dd>{data.integrations.devopsApi.tokenCount}</dd></div>
        <div><dt>Secret health</dt><dd>{data.metrics.highRisk} high risk / {data.metrics.stale} stale / {data.metrics.reused} reused</dd></div>
        <div><dt>Requests</dt><dd>{data.metrics.pendingRequests} pending</dd></div>
      </dl>
    </div>
  );
}

function PolicyPanel({ policies, canWrite, onChange }: { policies: Policies; canWrite: boolean; onChange: (patch: Partial<Policies>) => void }) {
  return (
    <div className="options-panel">
      <h2><Settings size={18} />Options</h2>
      <label><input type="checkbox" checked={policies.mfaRequired} disabled={!canWrite} onChange={() => onChange({ mfaRequired: !policies.mfaRequired })} />Require MFA for every unlock</label>
      <label><input type="checkbox" checked={policies.justInTimeAccess} disabled={!canWrite} onChange={() => onChange({ justInTimeAccess: !policies.justInTimeAccess })} />Use just-in-time access grants</label>
      <label>Automatically clear clipboard after<input type="number" disabled={!canWrite} value={policies.clipboardTtl} onChange={(event) => onChange({ clipboardTtl: Number(event.target.value) })} />seconds</label>
      <label>Lock workspace after<input type="number" disabled={!canWrite} value={policies.sessionMinutes} onChange={(event) => onChange({ sessionMinutes: Number(event.target.value) })} />minutes idle</label>
      <label>Default rotation interval<input type="number" disabled={!canWrite} value={policies.rotationDays} onChange={(event) => onChange({ rotationDays: Number(event.target.value) })} />days</label>
      <label>Minimum generated password length<input type="number" disabled={!canWrite} value={policies.minimumLength} onChange={(event) => onChange({ minimumLength: Number(event.target.value) })} /></label>
      <button><FileDown size={16} />Export policy evidence</button>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
