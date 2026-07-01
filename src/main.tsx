import "@vitejs/plugin-react/preamble";
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
  FilePlus2,
  Folder,
  FolderLock,
  Globe,
  History,
  KeyRound,
  LockKeyhole,
  LogOut,
  Plus,
  RefreshCw,
  RotateCcw,
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
import sentinelVaultMarkUrl from "./assets/sentinel-vault-mark.svg";
import { generatePassword as generateCredentialPassword } from "./lib/passwordGenerator";
import type { AccessRequest, AddSecret, AuditEvent, ConsoleData, IdentityStatus, Policies, Secret, UserRecord } from "./types";
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

function SentinelLogo({ size = "medium" }: { size?: "small" | "medium" | "large" }) {
  return <img className={`sentinel-logo ${size}`} src={sentinelVaultMarkUrl} alt="" aria-hidden="true" />;
}

function Login({ onLogin, initialError = "" }: { onLogin: (token: string, data: ConsoleData) => void; initialError?: string }) {
  const [email, setEmail] = useState("ada@defence.local");
  const [password, setPassword] = useState("Passw0rd!");
  const [idToken, setIdToken] = useState("");
  const [identity, setIdentity] = useState<IdentityStatus | null>(null);
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  const externalIdentity = identity?.mode && identity.mode !== "local";

  useEffect(() => {
    setError(initialError);
  }, [initialError]);

  useEffect(() => {
    api<{ identity: IdentityStatus }>("/api/identity/status")
      .then((response) => setIdentity(response.identity))
      .catch(() => setIdentity(null));
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const login = externalIdentity
        ? await api<{ token: string; user: UserRecord }>("/api/login/federated", { method: "POST", body: JSON.stringify({ idToken }) })
        : await api<{ token: string; user: UserRecord }>("/api/login", { method: "POST", body: JSON.stringify({ email, password }) });
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
        <header className="unlock-banner">
          <SentinelLogo size="large" />
          <div>
            <strong>Sentinel Vault</strong>
            <span>Enterprise Password Manager</span>
          </div>
        </header>
        <p className="login-intro">Sign in with a defence identity to access the multi-user password vault and audit-controlled workbench.</p>
        <form onSubmit={submit} className="unlock-form">
          {externalIdentity ? (
            <>
              <div className="identity-provider">
                <span>{identity?.name}</span>
                <strong>{identity?.issuer}</strong>
              </div>
              <label>
                Identity token
                <textarea value={idToken} onChange={(event) => setIdToken(event.target.value)} rows={5} spellCheck={false} />
              </label>
            </>
          ) : (
            <>
              <label>
                User name
                <input value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" />
              </label>
              <label>
                Master key
                <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" />
              </label>
            </>
          )}
          {error && <div className="error">{error}</div>}
          <button className="primary" disabled={busy}><LockKeyhole size={17} />{busy ? "Unlocking..." : externalIdentity ? "Sign In" : "Unlock Vault"}</button>
        </form>
        {!externalIdentity && (
          <div className="demo-accounts">
            <span>Demo identities</span>
            <button type="button" onClick={() => setEmail("ada@defence.local")}>Security Admin</button>
            <button type="button" onClick={() => setEmail("morgan@defence.local")}>Vault Operator</button>
            <button type="button" onClick={() => setEmail("iris@defence.local")}>Auditor</button>
            <small>Password: Passw0rd!</small>
          </div>
        )}
      </section>
    </main>
  );
}

function SplashState({ title, message }: { title: string; message: string }) {
  return (
    <main className="login-shell">
      <section className="unlock-card splash-card" aria-live="polite">
        <header className="unlock-banner">
          <SentinelLogo size="large" />
          <div>
            <strong>Sentinel Vault</strong>
            <span>Enterprise Password Manager</span>
          </div>
        </header>
        <h1>{title}</h1>
        <p>{message}</p>
        <div className="loading-bar"><span /></div>
      </section>
    </main>
  );
}

function App() {
  const [token, setToken] = useState(() => localStorage.getItem("sentinel-token") || "");
  const [data, setData] = useState<ConsoleData | null>(null);
  const [booting, setBooting] = useState(() => Boolean(localStorage.getItem("sentinel-token")));
  const [bootError, setBootError] = useState("");
  const [selectedGroup, setSelectedGroup] = useState("all");
  const [selectedSecretId, setSelectedSecretId] = useState("");
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<"entries" | "access" | "audit" | "users" | "policy" | "manage">("entries");
  const [reveal, setReveal] = useState<{ name: string; password: string; expiresIn: number } | null>(null);
  const [toast, setToast] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [locked, setLocked] = useState(false);
  const [addSecret, setAddSecret] = useState<AddSecret>(blankSecret());
  const [editSecret, setEditSecret] = useState<AddSecret>(blankSecret());
  const [newVault, setNewVault] = useState({ name: "", tenantId: "", classification: "SECRET", ownerUnit: "", members: "u1,u2" });
  const [integrationDraft, setIntegrationDraft] = useState({ siemWebhookUrl: "", siemWebhookSecret: "", itsmBaseUrl: "", itsmTicketPrefixes: "INC,CHG,REQ", devopsApiEnabled: false });
  const [generator, setGenerator] = useState({ length: 24, upper: true, lower: true, digits: true, symbols: true, noAmbiguous: true });

  const load = async (activeToken = token) => {
    if (!activeToken) return;
    const fresh = await api<ConsoleData>("/api/console", {}, activeToken);
    setData(fresh);
    setNewVault((current) => ({ ...current, tenantId: current.tenantId || fresh.tenants[0]?.id || "" }));
    setIntegrationDraft((current) => ({
      ...current,
      siemWebhookUrl: fresh.integrations.siem.webhookUrl,
      itsmBaseUrl: fresh.integrations.itsm.baseUrl,
      itsmTicketPrefixes: fresh.integrations.itsm.ticketPrefixes.join(","),
      devopsApiEnabled: fresh.integrations.devopsApi.enabled
    }));
    const firstVault = fresh.vaults[0]?.id || "";
    setAddSecret((current) => ({ ...current, vaultId: current.vaultId || firstVault }));
    if (!selectedSecretId && fresh.secrets[0]) setSelectedSecretId(fresh.secrets[0].id);
  };

  useEffect(() => {
    if (!token) {
      setBooting(false);
      return;
    }

    setBooting(true);
    load().catch((err) => {
      localStorage.removeItem("sentinel-token");
      setToken("");
      setBootError(err instanceof Error ? `Previous session could not be restored: ${err.message}` : "Previous session could not be restored");
    }).finally(() => setBooting(false));
  }, []);

  const onLogin = (nextToken: string, nextData: ConsoleData) => {
    localStorage.setItem("sentinel-token", nextToken);
    setToken(nextToken);
    setData(nextData);
    setBootError("");
    setSelectedGroup("all");
    setSelectedSecretId(nextData.secrets[0]?.id || "");
    setAddSecret(blankSecret(nextData.vaults[0]?.id || ""));
  };

  const signOut = () => {
    api("/api/logout", { method: "POST" }, token).catch(() => undefined);
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

  if (booting) return <SplashState title="Opening enterprise vault" message="Checking the saved session and loading the encrypted console state." />;
  if (!data || !token) return <Login onLogin={onLogin} initialError={bootError} />;

  const can = (permission: string) => data.user.permissions.includes(permission);
  const groupCounts = new Map<string, number>();
  data.secrets.forEach((secret) => groupCounts.set(secret.vaultId, (groupCounts.get(secret.vaultId) || 0) + 1));

  const filteredSecrets = data.secrets.filter((secret) => {
    const groupMatch = selectedGroup === "all" || selectedGroup === secret.vaultId || (selectedGroup === "shared" && secret.sharedWith.length > 1) || (selectedGroup === "risk" && secret.risk === "high");
    const text = [secret.name, secret.username, secret.url, secret.tags.join(" ")].join(" ").toLowerCase();
    return groupMatch && text.includes(query.toLowerCase());
  });
  const deletedSecrets = data.deletedSecrets.filter((secret) => {
    const text = [secret.name, secret.username, secret.url, secret.tags.join(" ")].join(" ").toLowerCase();
    return text.includes(query.toLowerCase());
  });
  const visibleSecrets = selectedGroup === "deleted" ? deletedSecrets : filteredSecrets;
  const selectedSecret = visibleSecrets.find((secret) => secret.id === selectedSecretId) || visibleSecrets[0] || (selectedGroup === "deleted" ? undefined : data.secrets[0]);
  const selectedVault = data.vaults.find((vault) => vault.id === selectedSecret?.vaultId);
  const viewingDeleted = selectedGroup === "deleted" || Boolean(selectedSecret?.deletedAt);

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

  const startEditSecret = (secret: Secret) => {
    setEditSecret({
      vaultId: secret.vaultId,
      type: secret.type,
      name: secret.name,
      username: secret.username,
      password: "",
      repeat: "",
      url: secret.url,
      tags: secret.tags.join(", "),
      notes: secret.notes
    });
    setEditOpen(true);
  };

  const submitEditSecret = (event: React.FormEvent) => {
    event.preventDefault();
    if (!selectedSecret) return;
    if (editSecret.password && editSecret.password !== editSecret.repeat) {
      setToast("Password and repeat fields do not match");
      return;
    }
    action(async () => {
      const patch: Record<string, unknown> = {
        type: editSecret.type,
        name: editSecret.name,
        username: editSecret.username,
        url: editSecret.url,
        tags: editSecret.tags,
        notes: editSecret.notes
      };
      if (editSecret.password) patch.password = editSecret.password;
      await api(`/api/secrets/${selectedSecret.id}`, { method: "PATCH", body: JSON.stringify(patch) }, token);
      setEditOpen(false);
    }, "Entry updated");
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

  const updateUserAdmin = (userId: string, patch: Partial<UserRecord>) => {
    action(async () => {
      await api(`/api/users/${userId}`, { method: "PATCH", body: JSON.stringify(patch) }, token);
    }, "User updated");
  };

  const submitVault = (event: React.FormEvent) => {
    event.preventDefault();
    action(async () => {
      await api("/api/vaults", { method: "POST", body: JSON.stringify({ ...newVault, members: newVault.members.split(",").map((member) => member.trim()) }) }, token);
      setNewVault({ name: "", tenantId: data.tenants[0]?.id || "", classification: "SECRET", ownerUnit: "", members: "u1,u2" });
    }, "Vault group created");
  };

  const submitIntegrations = (event: React.FormEvent) => {
    event.preventDefault();
    action(async () => {
      await api("/api/integrations/config", { method: "PATCH", body: JSON.stringify(integrationDraft) }, token);
      setIntegrationDraft((current) => ({ ...current, siemWebhookSecret: "" }));
    }, "Integration configuration updated");
  };

  const decideAccessRequest = (request: AccessRequest, decision: "approve" | "deny") => {
    action(async () => {
      await api(`/api/access-requests/${request.id}/${decision}`, { method: "POST", body: JSON.stringify({ minutes: 30 }) }, token);
    }, decision === "approve" ? "Temporary access approved" : "Temporary access denied");
  };

  return (
    <main className={`window-shell ${locked ? "is-locked" : ""}`}>
      <section className="titlebar">
        <div><SentinelLogo size="small" />Sentinel.kdbx - Sentinel Vault Enterprise</div>
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
        <button title="Edit selected entry" disabled={!selectedSecret || viewingDeleted || !can("vault:write")} onClick={() => selectedSecret && startEditSecret(selectedSecret)}><Edit3 size={18} /></button>
        <button title="Delete selected entry" disabled={!selectedSecret || viewingDeleted || !can("vault:write")} onClick={() => selectedSecret && action(async () => { await api(`/api/secrets/${selectedSecret.id}`, { method: "DELETE" }, token); setSelectedGroup("deleted"); setSelectedSecretId(selectedSecret.id); }, "Entry moved to deleted items")}><Trash2 size={18} /></button>
        <span className="divider" />
        <button title="Copy user name" disabled={!selectedSecret} onClick={() => selectedSecret && copyUsername(selectedSecret)}><User size={18} /></button>
        <button title="Reveal password" disabled={!selectedSecret || viewingDeleted} onClick={() => selectedSecret && revealSecret(selectedSecret)}><KeyRound size={18} /></button>
        <button title="Rotate password" disabled={!selectedSecret || viewingDeleted || !can("vault:write")} onClick={() => selectedSecret && action(async () => { await api(`/api/secrets/${selectedSecret.id}/rotate`, { method: "POST" }, token); }, "Entry password rotated")}><RefreshCw size={18} /></button>
        <button title="Share entry" disabled={!selectedSecret || viewingDeleted || !can("vault:share")} onClick={() => selectedSecret && action(async () => { await api(`/api/secrets/${selectedSecret.id}/share`, { method: "POST", body: JSON.stringify({ userId: "u3" }) }, token); }, "Entry shared with auditor")}><UserCog size={18} /></button>
        <span className="divider" />
        <button title="Lock workspace" onClick={() => setLocked(true)}><LockKeyhole size={18} /></button>
        <button title="Sign out" onClick={signOut}><LogOut size={18} /></button>
        <label className="quick-search">
          <Search size={16} />
          <input placeholder="Search..." value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
      </section>

      <section className="database-tabs">
        <button className="active"><SentinelLogo size="small" />Sentinel.kdbx</button>
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
          <TreeButton active={selectedGroup === "deleted"} icon={<Trash2 />} label="Deleted Items" meta={`${data.deletedSecrets.length} recoverable`} onClick={() => setSelectedGroup("deleted")} />
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
                {visibleSecrets.map((secret) => (
                  <button className={`entry-row ${selectedSecret?.id === secret.id ? "selected" : ""}`} key={secret.id} onClick={() => setSelectedSecretId(secret.id)} role="row">
                    <span><Globe size={16} />{secret.name}<small>{secret.type.replace("_", " ")}</small></span>
                    <span>{secret.username}</span>
                    <span>••••••••••••</span>
                    <span>{secret.url}</span>
                    <span>{new Date(secret.deletedAt || secret.rotatedAt).toLocaleDateString()}</span>
                    <span><meter min={0} max={100} value={secret.strength} />{secret.strength}%</span>
                  </button>
                ))}
                {!visibleSecrets.length && (
                  <div className="empty-state" role="row">
                    <Search size={22} />
                    <strong>{selectedGroup === "deleted" ? "No deleted entries" : "No matching entries"}</strong>
                    <span>{selectedGroup === "deleted" ? "Deleted credentials will appear here until restored." : "Adjust the search text or select a different vault group."}</span>
                  </div>
                )}
              </div>

              {selectedSecret && (
                <section className="details-pane">
                  <div>
                    <h2>{selectedSecret.name}</h2>
                    <p>{selectedVault?.name} · {selectedVault?.classification} · {selectedSecret.tags.join(", ") || "No tags"}</p>
                  </div>
                  <div className="detail-actions">
                    {viewingDeleted ? (
                      <button disabled={!can("vault:write")} onClick={() => action(async () => { await api(`/api/secrets/${selectedSecret.id}/restore`, { method: "POST" }, token); setSelectedGroup("all"); }, "Entry restored")}><RotateCcw size={16} />Restore</button>
                    ) : (
                      <>
                        <button onClick={() => copyUsername(selectedSecret)}><Clipboard size={16} />Copy User</button>
                        <button onClick={() => revealSecret(selectedSecret)}><Eye size={16} />Reveal</button>
                        <button disabled={!can("vault:write")} onClick={() => startEditSecret(selectedSecret)}><Edit3 size={16} />Edit</button>
                        <button disabled={!can("vault:write")} onClick={() => action(async () => { await api(`/api/secrets/${selectedSecret.id}/rotate`, { method: "POST" }, token); }, "Entry password rotated")}><Shuffle size={16} />Rotate</button>
                      </>
                    )}
                  </div>
                  <dl>
                    <div><dt>User Name</dt><dd>{selectedSecret.username}</dd></div>
                    <div><dt>Type</dt><dd>{selectedSecret.type.replace("_", " ")}</dd></div>
                    <div><dt>URL</dt><dd>{selectedSecret.url}</dd></div>
                    <div><dt>Risk</dt><dd className={`risk ${selectedSecret.risk}`}>{selectedSecret.risk}</dd></div>
                    <div><dt>Approval</dt><dd>{selectedSecret.approvalsRequired ? "Required" : "Standard"}</dd></div>
                    <div><dt>Shared With</dt><dd>{selectedSecret.sharedWith.length} identities</dd></div>
                    <div><dt>Versions</dt><dd>{selectedSecret.history.length}</dd></div>
                    {selectedSecret.deletedAt && <div><dt>Deleted</dt><dd>{new Date(selectedSecret.deletedAt).toLocaleString()}</dd></div>}
                  </dl>
                  <textarea value={`${selectedSecret.notes || "Entry notes"}\nOwner unit: ${selectedVault?.ownerUnit || "Unknown"}\nRotation policy: ${data.policies.rotationDays} days\nLast modified: ${new Date(selectedSecret.rotatedAt).toLocaleString()}`} readOnly />
                  <VersionHistory secret={selectedSecret} canRestore={can("vault:write") && !viewingDeleted} onRestore={(index) => action(async () => { await api(`/api/secrets/${selectedSecret.id}/versions/${index}/restore`, { method: "POST" }, token); }, "Entry version restored")} />
                </section>
              )}
              {!selectedSecret && (
                <section className="details-pane empty-details">
                  <div>
                    <h2>No entry selected</h2>
                    <p>Select a credential entry to inspect its metadata, access controls, and rotation posture.</p>
                  </div>
                </section>
              )}
            </>
          )}

          {tab === "access" && <AccessTable requests={data.accessRequests} canApprove={can("vault:share")} onDecision={decideAccessRequest} />}
          {tab === "audit" && <AuditTable events={data.audit} />}
          {tab === "users" && <UserTable users={data.users} canManage={can("policy:write")} onChange={updateUserAdmin} />}
          {tab === "policy" && <PolicyPanel policies={data.policies} canWrite={can("policy:write")} onChange={updatePolicy} />}
          {tab === "manage" && <ManagementPanel data={data} canManage={can("policy:write")} newVault={newVault} onVaultChange={setNewVault} onVaultSubmit={submitVault} integrationDraft={integrationDraft} onIntegrationChange={setIntegrationDraft} onIntegrationSubmit={submitIntegrations} />}
        </section>
      </section>

      <section className="statusbar">
        <span>{data.vaults.length} groups / {visibleSecrets.length} entries</span>
        <span>{selectedSecret ? `1 of ${visibleSecrets.length} selected` : "No entry selected"}</span>
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

      {editOpen && selectedSecret && (
        <div className="modal-backdrop" onClick={() => setEditOpen(false)}>
          <dialog open className="entry-dialog" onClick={(event) => event.stopPropagation()}>
            <header>
              <Edit3 size={28} />
              <div><h2>Edit Entry</h2><p>Update credential metadata or rotate the stored secret value.</p></div>
            </header>
            <form onSubmit={submitEditSecret}>
              <div className="dialog-tabs"><span className="active">Entry</span><span>History</span><span>Security</span></div>
              <label>Group<select value={editSecret.vaultId} disabled>{data.vaults.map((vault) => <option value={vault.id} key={vault.id}>{vault.name}</option>)}</select></label>
              <label>Secret type<select value={editSecret.type} onChange={(event) => setEditSecret({ ...editSecret, type: event.target.value })}>
                <option value="password">Password</option>
                <option value="api_key">API key</option>
                <option value="ssh_key">SSH key</option>
                <option value="certificate">Certificate</option>
                <option value="token">Token</option>
                <option value="connection_string">Connection string</option>
              </select></label>
              <label>Title<input value={editSecret.name} onChange={(event) => setEditSecret({ ...editSecret, name: event.target.value })} /></label>
              <label>User name<input value={editSecret.username} onChange={(event) => setEditSecret({ ...editSecret, username: event.target.value })} /></label>
              <label>New password<div className="password-line"><input value={editSecret.password} placeholder="Leave blank to keep current value" onChange={(event) => setEditSecret({ ...editSecret, password: event.target.value })} /><button type="button" onClick={() => {
                const password = generateCredentialPassword(generator);
                setEditSecret((current) => ({ ...current, password, repeat: password }));
              }}><WandSparkles size={16} /></button></div></label>
              <label>Repeat<input value={editSecret.repeat} onChange={(event) => setEditSecret({ ...editSecret, repeat: event.target.value })} /></label>
              <label>URL<input value={editSecret.url} onChange={(event) => setEditSecret({ ...editSecret, url: event.target.value })} /></label>
              <label>Tags<input value={editSecret.tags} onChange={(event) => setEditSecret({ ...editSecret, tags: event.target.value })} /></label>
              <label>Notes<textarea value={editSecret.notes} onChange={(event) => setEditSecret({ ...editSecret, notes: event.target.value })} /></label>
              <footer>
                <button type="button" className="secondary" onClick={() => setEditOpen(false)}>Cancel</button>
                <button className="primary" disabled={!can("vault:write")}>Save Entry</button>
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

function VersionHistory({ secret, canRestore, onRestore }: { secret: Secret; canRestore: boolean; onRestore: (index: number) => void }) {
  if (!secret.history.length) {
    return (
      <div className="version-history empty-version-history">
        <History size={16} />
        <span>No previous versions stored for this entry.</span>
      </div>
    );
  }

  return (
    <div className="version-history">
      <header><History size={16} />Version History</header>
      {secret.history.map((version) => (
        <div className="version-line" key={`${secret.id}-${version.index}`}>
          <span>{new Date(version.rotatedAt).toLocaleString()}</span>
          <small>{version.rotatedByName}</small>
          <button disabled={!canRestore} onClick={() => onRestore(version.index)}>Restore</button>
        </div>
      ))}
    </div>
  );
}

function UserTable({ users, canManage, onChange }: { users: UserRecord[]; canManage: boolean; onChange: (userId: string, patch: Partial<UserRecord>) => void }) {
  return (
    <div className="utility-table">
      <div className="table-header users"><span>Name</span><span>Email</span><span>Role</span><span>Status</span><span>Unit</span></div>
      {users.map((user) => (
        <div className="user-line" key={user.id}>
          <strong>{user.name}</strong>
          <span>{user.email}</span>
          <span>
            <select disabled={!canManage} value={user.role} onChange={(event) => onChange(user.id, { role: event.target.value as UserRecord["role"] })}>
              <option value="SECURITY_ADMIN">Security Admin</option>
              <option value="VAULT_OPERATOR">Vault Operator</option>
              <option value="AUDITOR">Auditor</option>
            </select>
          </span>
          <span>
            <label className="inline-check"><input type="checkbox" checked={user.enabled} disabled={!canManage} onChange={(event) => onChange(user.id, { enabled: event.target.checked })} />Enabled</label>
          </span>
          <span>{user.unit}</span>
        </div>
      ))}
    </div>
  );
}

function ManagementPanel({ data, canManage, newVault, onVaultChange, onVaultSubmit, integrationDraft, onIntegrationChange, onIntegrationSubmit }: {
  data: ConsoleData;
  canManage: boolean;
  newVault: { name: string; tenantId: string; classification: string; ownerUnit: string; members: string };
  onVaultChange: (vault: { name: string; tenantId: string; classification: string; ownerUnit: string; members: string }) => void;
  onVaultSubmit: (event: React.FormEvent) => void;
  integrationDraft: { siemWebhookUrl: string; siemWebhookSecret: string; itsmBaseUrl: string; itsmTicketPrefixes: string; devopsApiEnabled: boolean };
  onIntegrationChange: (draft: { siemWebhookUrl: string; siemWebhookSecret: string; itsmBaseUrl: string; itsmTicketPrefixes: string; devopsApiEnabled: boolean }) => void;
  onIntegrationSubmit: (event: React.FormEvent) => void;
}) {
  return (
    <div className="options-panel management-panel">
      <h2><Settings size={18} />Management</h2>
      <dl>
        <div><dt>Identity</dt><dd>{data.identity.name} ({data.identity.mode})</dd></div>
        <div><dt>Tenants</dt><dd>{data.metrics.tenants} hierarchy nodes</dd></div>
        <div><dt>Sessions</dt><dd>{data.session.activeSessions} active / {data.session.reviewable} reviewable / {data.session.knownDevices} devices / {data.session.ttlMinutes} min TTL</dd></div>
        <div><dt>Crypto</dt><dd>{data.crypto.algorithm} / {data.crypto.keyVersion} / {data.crypto.keyProvider.provider}</dd></div>
        <div><dt>Storage</dt><dd>{data.storage.mode} v{data.storage.stateVersion}</dd></div>
        <div><dt>Backups</dt><dd>{data.storage.backups.length} retained / {data.storage.backups.filter((backup) => backup.verified).length} verified</dd></div>
        <div><dt>Audit integrity</dt><dd>{data.auditIntegrity.verified ? "Verified" : "Attention"} / {data.auditIntegrity.checked} chained</dd></div>
        <div><dt>SIEM</dt><dd>{data.integrations.siem.mode} / {data.integrations.siem.signing ? "signed" : "unsigned"} / {data.integrations.siem.replayWindowSeconds}s replay window / {data.integrations.siem.pending} pending / {data.integrations.siem.failed} failed</dd></div>
        <div><dt>DevOps tokens</dt><dd>{data.integrations.devopsApi.tokenCount}</dd></div>
        <div><dt>Secret health</dt><dd>{data.metrics.highRisk} high risk / {data.metrics.stale} stale / {data.metrics.reused} reused</dd></div>
        <div><dt>Requests</dt><dd>{data.metrics.pendingRequests} pending</dd></div>
      </dl>
      <form className="vault-admin-form" onSubmit={onVaultSubmit}>
        <h3><FolderLock size={16} />Create Vault Group</h3>
        <label>Name<input value={newVault.name} disabled={!canManage} onChange={(event) => onVaultChange({ ...newVault, name: event.target.value })} /></label>
        <label>Tenant<select value={newVault.tenantId} disabled={!canManage} onChange={(event) => onVaultChange({ ...newVault, tenantId: event.target.value })}>
          {data.tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
        </select></label>
        <label>Classification<select value={newVault.classification} disabled={!canManage} onChange={(event) => onVaultChange({ ...newVault, classification: event.target.value })}>
          <option value="OFFICIAL">OFFICIAL</option>
          <option value="OFFICIAL-SENSITIVE">OFFICIAL-SENSITIVE</option>
          <option value="SECRET">SECRET</option>
          <option value="TOP SECRET">TOP SECRET</option>
        </select></label>
        <label>Owner unit<input value={newVault.ownerUnit} disabled={!canManage} onChange={(event) => onVaultChange({ ...newVault, ownerUnit: event.target.value })} /></label>
        <label>Members<input value={newVault.members} disabled={!canManage} onChange={(event) => onVaultChange({ ...newVault, members: event.target.value })} /></label>
        <button className="secondary" disabled={!canManage || !newVault.name.trim()}><Plus size={16} />Create Group</button>
      </form>
      <form className="vault-admin-form" onSubmit={onIntegrationSubmit}>
        <h3><Settings size={16} />Integration Configuration</h3>
        <label>SIEM webhook<input value={integrationDraft.siemWebhookUrl} disabled={!canManage} onChange={(event) => onIntegrationChange({ ...integrationDraft, siemWebhookUrl: event.target.value })} /></label>
        <label>SIEM signing secret<input type="password" value={integrationDraft.siemWebhookSecret} placeholder={data.integrations.siem.signing ? "Configured" : "Not configured"} disabled={!canManage} onChange={(event) => onIntegrationChange({ ...integrationDraft, siemWebhookSecret: event.target.value })} /></label>
        <label>ITSM base URL<input value={integrationDraft.itsmBaseUrl} disabled={!canManage} onChange={(event) => onIntegrationChange({ ...integrationDraft, itsmBaseUrl: event.target.value })} /></label>
        <label>Ticket prefixes<input value={integrationDraft.itsmTicketPrefixes} disabled={!canManage} onChange={(event) => onIntegrationChange({ ...integrationDraft, itsmTicketPrefixes: event.target.value })} /></label>
        <label className="inline-check"><input type="checkbox" checked={integrationDraft.devopsApiEnabled} disabled={!canManage} onChange={(event) => onIntegrationChange({ ...integrationDraft, devopsApiEnabled: event.target.checked })} />Enable DevOps API</label>
        <button className="secondary" disabled={!canManage}><Save size={16} />Save Integrations</button>
      </form>
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
