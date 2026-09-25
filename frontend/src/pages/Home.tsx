import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  BarChart3,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Download,
  FileJson,
  FileText,
  Fingerprint,
  Globe2,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Timer,
  UserRound,
  Users,
  X,
  XCircle,
} from "lucide-react";

type Role = "Admin" | "Viewer";
type ReviewStatus = "unreviewed" | "confirmed" | "false_positive";
type Severity = "Low" | "Medium" | "High" | "Critical";

type Incident = {
  id: number;
  timestamp: string;
  sourceIp: string;
  country: string;
  incidentType: string;
  severity: Severity;
  mitreTechnique: string;
  details: string;
  reviewStatus: ReviewStatus;
};

type Account = { username: string; password: string; role: Role };

const ADMIN_CODE = "CGATE-ADMIN-2026";
const SESSION_KEY = "canarygate-session-v2";
const USERS_KEY = "canarygate-users-v2";
const INCIDENTS_KEY = "canarygate-incidents-v2";

const seedIncidents: Incident[] = [
  { id: 1042, timestamp: "2026-09-25T12:08:00Z", sourceIp: "127.0.0.1", country: "Pakistan", incidentType: "CANARY_TRIGGERED", severity: "Critical", mitreTechnique: "T1078", details: "Decoy credential used from an unexpected machine identity.", reviewStatus: "unreviewed" },
  { id: 1041, timestamp: "2026-09-25T12:05:00Z", sourceIp: "127.0.0.1", country: "Pakistan", incidentType: "BLOCKED_HIGH_RISK", severity: "High", mitreTechnique: "T1190", details: "Risk score exceeded the policy threshold after a burst of requests.", reviewStatus: "confirmed" },
  { id: 1040, timestamp: "2026-09-25T12:03:00Z", sourceIp: "127.0.0.1", country: "Pakistan", incidentType: "ALLOWED_WITH_WARNING", severity: "Medium", mitreTechnique: "T1071.001", details: "Known agent identity moved outside its normal request window.", reviewStatus: "unreviewed" },
  { id: 1039, timestamp: "2026-09-25T11:44:00Z", sourceIp: "45.10.20.30", country: "Germany", incidentType: "CANARY_TRIGGERED", severity: "Critical", mitreTechnique: "T1552.001", details: "Canary token replay detected after impossible geographic velocity.", reviewStatus: "false_positive" },
  { id: 1038, timestamp: "2026-09-25T11:31:00Z", sourceIp: "99.99.99.99", country: "Russia", incidentType: "BLOCKED_HIGH_RISK", severity: "High", mitreTechnique: "T1059", details: "Suspicious path traversal payload blocked at the proxy edge.", reviewStatus: "confirmed" },
  { id: 1037, timestamp: "2026-09-25T11:12:00Z", sourceIp: "172.34.54.67", country: "USA", incidentType: "ALLOWED_WITH_WARNING", severity: "Medium", mitreTechnique: "T1110", details: "Repeated authentication attempts from a low-trust network.", reviewStatus: "unreviewed" },
  { id: 1036, timestamp: "2026-09-25T10:54:00Z", sourceIp: "45.10.20.30", country: "Germany", incidentType: "BLOCKED_HIGH_RISK", severity: "High", mitreTechnique: "T1059.004", details: "Header injection signature matched the active deception policy.", reviewStatus: "unreviewed" },
  { id: 1035, timestamp: "2026-09-25T10:22:00Z", sourceIp: "127.0.0.1", country: "Pakistan", incidentType: "ALLOWED_WITH_WARNING", severity: "Low", mitreTechnique: "T1071.001", details: "Request accepted with elevated monitoring enabled.", reviewStatus: "false_positive" },
  { id: 1034, timestamp: "2026-09-25T09:48:00Z", sourceIp: "172.34.54.67", country: "USA", incidentType: "CANARY_TRIGGERED", severity: "Critical", mitreTechnique: "T1552.001", details: "Machine identity presented a known decoy token.", reviewStatus: "confirmed" },
  { id: 1033, timestamp: "2026-09-25T09:04:00Z", sourceIp: "45.10.20.30", country: "Germany", incidentType: "ALLOWED_WITH_WARNING", severity: "Medium", mitreTechnique: "T1078", details: "Geo-velocity signal requires analyst review.", reviewStatus: "unreviewed" },
  { id: 1032, timestamp: "2026-09-25T08:46:00Z", sourceIp: "99.99.99.99", country: "Russia", incidentType: "BLOCKED_HIGH_RISK", severity: "High", mitreTechnique: "T1190", details: "Oversized payload rejected before reaching the protected service.", reviewStatus: "confirmed" },
  { id: 1031, timestamp: "2026-09-25T08:18:00Z", sourceIp: "172.34.54.67", country: "USA", incidentType: "ALLOWED_WITH_WARNING", severity: "Low", mitreTechnique: "T1071.001", details: "New client fingerprint observed for an existing identity.", reviewStatus: "unreviewed" },
];

const defaultUsers: Account[] = [
  { username: "admin", password: "admin123", role: "Admin" },
  { username: "viewer", password: "viewer123", role: "Viewer" },
];

function readStorage<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage<T>(key: string, value: T) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // The dashboard still works in privacy-restricted preview sessions.
  }
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", month: "short", day: "numeric" }).format(new Date(value));
}

function statusLabel(status: ReviewStatus) {
  return status === "false_positive" ? "False positive" : status[0].toUpperCase() + status.slice(1);
}

function downloadFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function AuthScreen({ onLogin }: { onLogin: (account: Account) => void }) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [adminCode, setAdminCode] = useState("");
  const [error, setError] = useState("");

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    const cleanUsername = username.trim();
    if (!cleanUsername || !password) {
      setError("Username and password are required.");
      return;
    }
    const users = readStorage<Account[]>(USERS_KEY, defaultUsers);
    if (mode === "login") {
      const account = users.find((item) => item.username.toLowerCase() === cleanUsername.toLowerCase() && item.password === password);
      if (!account) {
        setError("Invalid credentials. Try admin / admin123 or viewer / viewer123.");
        return;
      }
      onLogin(account);
      return;
    }
    if (users.some((item) => item.username.toLowerCase() === cleanUsername.toLowerCase())) {
      setError("That username already exists.");
      return;
    }
    if (adminCode && adminCode !== ADMIN_CODE) {
      setError("Incorrect admin code. Leave it blank for a Viewer account.");
      return;
    }
    const account: Account = { username: cleanUsername, password, role: adminCode ? "Admin" : "Viewer" };
    writeStorage(USERS_KEY, [...users, account]);
    onLogin(account);
  };

  return (
    <div className="auth-shell">
      <div className="auth-orbit orbit-one" />
      <div className="auth-orbit orbit-two" />
      <section className="auth-card">
        <div className="brand-mark large"><Shield size={25} /></div>
        <div className="eyebrow">CANARYGATE / SECURE CONSOLE</div>
        <h1>Machine identity defense, without the noise.</h1>
        <p className="auth-copy">Context-aware access control, canary deception, and analyst review in one calm operational view.</p>
        <div className="auth-tabs">
          <button className={mode === "login" ? "active" : ""} onClick={() => { setMode("login"); setError(""); }}>Log in</button>
          <button className={mode === "signup" ? "active" : ""} onClick={() => { setMode("signup"); setError(""); }}>Sign up</button>
        </div>
        <form onSubmit={submit} className="auth-form">
          <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="e.g. analyst" autoComplete="username" /></label>
          <label>Password<input value={password} onChange={(event) => setPassword(event.target.value)} type="password" placeholder="••••••••" autoComplete={mode === "login" ? "current-password" : "new-password"} /></label>
          {mode === "signup" && <label>Admin code <span className="muted">(optional)</span><input value={adminCode} onChange={(event) => setAdminCode(event.target.value)} type="password" placeholder="CGATE-ADMIN-2026" /></label>}
          {error && <div className="form-error"><AlertTriangle size={15} />{error}</div>}
          <button className="primary-button" type="submit">{mode === "login" ? "Enter console" : "Create account"}<ChevronRight size={16} /></button>
        </form>
        <div className="demo-hint"><span><Lock size={13} /> Local demo access</span><span>Admin: admin / admin123</span><span>Viewer: viewer / viewer123</span></div>
      </section>
    </div>
  );
}

export default function Home() {
  const [session, setSession] = useState<Account | null>(() => readStorage<Account | null>(SESSION_KEY, null));
  const [incidents, setIncidents] = useState<Incident[]>(() => readStorage(INCIDENTS_KEY, seedIncidents));
  const [selected, setSelected] = useState<Incident | null>(null);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("All events");
  const [severityFilter, setSeverityFilter] = useState("All severities");
  const [activeNav, setActiveNav] = useState("Overview");
  const [mobileNav, setMobileNav] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast] = useState("");

  useEffect(() => {
    let active = true;
    fetch("/dashboard/incidents")
      .then((response) => response.ok ? response.json() : null)
      .then((data: unknown) => {
        if (active && Array.isArray(data) && data.length > 0) {
          setIncidents(data as Incident[]);
          writeStorage(INCIDENTS_KEY, data as Incident[]);
        }
      })
      .catch(() => {
        // Keep the seeded demo feed when the Python API is not running.
      });
    return () => { active = false; };
  }, []);

  const notify = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 2400);
  };

  const login = (account: Account) => {
    setSession(account);
    writeStorage(SESSION_KEY, account);
  };

  const logout = () => {
    setSession(null);
    setSelected(null);
    localStorage.removeItem(SESSION_KEY);
  };

  const updateIncident = (id: number, status: ReviewStatus) => {
    if (session?.role !== "Admin") {
      notify("Admin access is required to update review status.");
      return;
    }
    void fetch(`/dashboard/incidents/${id}/review`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "X-Dashboard-Role": session.role },
      body: JSON.stringify({ reviewStatus: status }),
    }).catch(() => {
      // Keep local optimistic state if the API is offline during a demo.
    });
    const updated = incidents.map((incident) => incident.id === id ? { ...incident, reviewStatus: status } : incident);
    setIncidents(updated);
    writeStorage(INCIDENTS_KEY, updated);
    setSelected((current) => current && current.id === id ? { ...current, reviewStatus: status } : current);
    notify(`Incident #${id} marked ${statusLabel(status).toLowerCase()}.`);
  };

  const refresh = () => {
    setRefreshing(true);
    window.setTimeout(() => {
      setRefreshing(false);
      notify("Live incident feed refreshed.");
    }, 650);
  };

  const filteredIncidents = useMemo(() => incidents.filter((incident) => {
    const matchesQuery = !query || [incident.sourceIp, incident.country, incident.incidentType, incident.details, incident.mitreTechnique].join(" ").toLowerCase().includes(query.toLowerCase());
    const matchesType = typeFilter === "All events" || incident.incidentType === typeFilter;
    const matchesSeverity = severityFilter === "All severities" || incident.severity === severityFilter;
    return matchesQuery && matchesType && matchesSeverity;
  }), [incidents, query, typeFilter, severityFilter]);

  const metrics = useMemo(() => ({
    total: incidents.length,
    canary: incidents.filter((item) => item.incidentType === "CANARY_TRIGGERED").length,
    blocked: incidents.filter((item) => item.incidentType === "BLOCKED_HIGH_RISK").length,
    warnings: incidents.filter((item) => item.incidentType === "ALLOWED_WITH_WARNING").length,
    falsePositives: incidents.filter((item) => item.reviewStatus === "false_positive").length,
  }), [incidents]);

  const correlated = useMemo(() => Object.entries(incidents.reduce<Record<string, Incident[]>>((groups, incident) => {
    (groups[incident.sourceIp] ||= []).push(incident);
    return groups;
  }, {})).filter(([, group]) => group.length >= 3).map(([sourceIp, group]) => ({ sourceIp, count: group.length, country: group[0].country })), [incidents]);

  const countryCounts = useMemo(() => Object.entries(incidents.reduce<Record<string, number>>((groups, incident) => {
    groups[incident.country] = (groups[incident.country] || 0) + 1;
    return groups;
  }, {})).sort((a, b) => b[1] - a[1]), [incidents]);

  const exportCsv = () => {
    const header = "id,timestamp,source_ip,country,incident_type,severity,mitre_technique,review_status,details";
    const rows = incidents.map((item) => [item.id, item.timestamp, item.sourceIp, item.country, item.incidentType, item.severity, item.mitreTechnique, item.reviewStatus, `"${item.details.replaceAll('"', '""')}"`].join(","));
    downloadFile("canarygate-incidents.csv", [header, ...rows].join("\n"), "text/csv");
    notify("CSV export downloaded.");
  };

  const exportJson = () => {
    downloadFile("canarygate-incidents.json", JSON.stringify(incidents, null, 2), "application/json");
    notify("JSON export downloaded.");
  };

  const printPdf = () => {
    notify("Print dialog opened — choose ‘Save as PDF’ to create the report.");
    window.setTimeout(() => window.print(), 180);
  };

  if (!session) return <AuthScreen onLogin={login} />;
  const isAdmin = session.role === "Admin";

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? "open" : ""}`}>
        <div className="sidebar-brand"><div className="brand-mark"><Shield size={19} /></div><div><strong>CanaryGate</strong><span>SOC CONSOLE <i>v2.4</i></span></div><button className="mobile-close" onClick={() => setMobileNav(false)}><X size={18} /></button></div>
        <div className="sidebar-label">Workspace</div>
        <nav className="main-nav">
          {[{ name: "Overview", icon: LayoutDashboard }, { name: "Incidents", icon: ShieldAlert }, { name: "Identity graph", icon: Fingerprint }, { name: "Threat surface", icon: Globe2 }].map(({ name, icon: Icon }) => <button key={name} className={activeNav === name ? "active" : ""} onClick={() => { setActiveNav(name); setMobileNav(false); }}><Icon size={17} /><span>{name}</span>{name === "Incidents" && <b>{incidents.length}</b>}</button>)}
        </nav>
        <div className="sidebar-label">Operations</div>
        <nav className="main-nav">
          {[{ name: "Reports", icon: BarChart3 }, { name: "Team access", icon: Users }].map(({ name, icon: Icon }) => <button key={name} className={activeNav === name ? "active" : ""} onClick={() => { setActiveNav(name); setMobileNav(false); }}><Icon size={17} /><span>{name}</span></button>)}
        </nav>
        <div className="sidebar-spacer" />
        <div className="system-card"><div className="system-top"><span className="pulse-dot" />Systems nominal</div><p>Proxy and deception engine are reporting normally.</p><div className="system-line"><span>API gateway</span><strong>99.98%</strong></div><div className="system-line"><span>Last heartbeat</span><strong>18 sec ago</strong></div></div>
        <div className="sidebar-account"><div className="avatar">{session.username.slice(0, 1).toUpperCase()}</div><div className="account-copy"><strong>{session.username}</strong><span>{session.role} access</span></div><button onClick={logout} title="Log out"><LogOut size={16} /></button></div>
      </aside>
      {mobileNav && <button className="scrim" onClick={() => setMobileNav(false)} aria-label="Close navigation" />}
      <main className="main-content">
        <header className="topbar"><button className="mobile-menu" onClick={() => setMobileNav(true)}><Menu size={20} /></button><div className="breadcrumb"><span>Security operations</span><ChevronRight size={14} /><strong>{activeNav}</strong></div><div className="top-actions"><div className="live-indicator"><span className="pulse-dot" />Live monitoring</div><button className="icon-button" onClick={refresh} title="Refresh feed"><RefreshCw size={17} className={refreshing ? "spin" : ""} /></button><button className="user-chip" onClick={logout}><span className="avatar small">{session.username.slice(0, 1).toUpperCase()}</span><span>{session.username}</span><LogOut size={14} /></button></div></header>
        <div className="content-wrap">
          <section className="hero-row"><div><div className="eyebrow">FRIDAY, 25 SEPTEMBER 2026 / ZERO-TRUST MONITORING</div><h1>Good morning, {session.username}.</h1><p>Here’s the current posture across your machine-identity perimeter.</p></div><div className="hero-actions"><span className={`role-pill ${isAdmin ? "admin" : "viewer"}`}><UserRound size={14} />{session.role} mode</span><button className="secondary-button" onClick={refresh}><RefreshCw size={15} className={refreshing ? "spin" : ""} />Refresh data</button></div></section>
          {!isAdmin && <div className="readonly-banner"><Lock size={16} /><span><strong>Read-only mode.</strong> You can inspect incidents and analytics. Admin accounts can update reviews and export reports.</span></div>}
          <section className="metric-grid">
            <div className="metric-card featured"><div className="metric-head"><span>Total incidents</span><Activity size={16} /></div><div className="metric-value">{metrics.total}</div><div className="metric-foot"><span className="up">+12.4%</span><span>vs previous window</span></div><div className="sparkline"><i /><i /><i /><i /><i /><i /><i /><i /><i /></div></div>
            <div className="metric-card"><div className="metric-head"><span>Canary triggers</span><span className="metric-icon red"><ShieldAlert size={15} /></span></div><div className="metric-value">{metrics.canary}</div><div className="metric-foot"><span className="danger">+2</span><span>high confidence</span></div></div>
            <div className="metric-card"><div className="metric-head"><span>Blocked high risk</span><span className="metric-icon orange"><XCircle size={15} /></span></div><div className="metric-value">{metrics.blocked}</div><div className="metric-foot"><span className="up">100%</span><span>policy enforced</span></div></div>
            <div className="metric-card"><div className="metric-head"><span>Allowed + warning</span><span className="metric-icon yellow"><AlertTriangle size={15} /></span></div><div className="metric-value">{metrics.warnings}</div><div className="metric-foot"><span className="neutral">steady</span><span>under observation</span></div></div>
            <div className="metric-card"><div className="metric-head"><span>False positives</span><span className="metric-icon green"><CheckCircle2 size={15} /></span></div><div className="metric-value">{metrics.falsePositives}</div><div className="metric-foot"><span className="up">-8.1%</span><span>reviewed by analysts</span></div></div>
          </section>
          <section className="visual-grid"><div className="panel chart-panel"><div className="panel-heading"><div><div className="panel-kicker"><BarChart3 size={14} /> RISK TELEMETRY</div><h2>Threat signal volume</h2></div><select className="compact-select"><option>Last 24 hours</option><option>Last 7 days</option></select></div><div className="chart-area"><div className="chart-y"><span>40</span><span>30</span><span>20</span><span>10</span><span>0</span></div><div className="chart-bars">{[22, 31, 18, 26, 20, 34, 25, 18, 30, 23, 37, 29, 32, 21, 27, 35, 24, 30, 20, 25, 18, 32, 27, 38].map((height, index) => <div className="bar-wrap" key={index}><div className={`bar ${height > 33 ? "hot" : ""}`} style={{ height: `${height * 2.05}px` }} /></div>)}</div></div><div className="chart-legend"><span><i className="legend-dot cyan" />All signals</span><span><i className="legend-dot coral" />High risk events</span><span className="chart-time">00:00 <b>06:00</b> 12:00 <b>18:00</b> now</span></div></div><div className="panel surface-panel"><div className="panel-heading"><div><div className="panel-kicker"><Globe2 size={14} /> THREAT SURFACE</div><h2>Origin distribution</h2></div><button className="link-button" onClick={() => setActiveNav("Threat surface")}>Full view <ChevronRight size={14} /></button></div><div className="origin-list">{countryCounts.map(([country, count], index) => <div className="origin-row" key={country}><div className="origin-name"><span className={`country-dot dot-${index}`} />{country}</div><div className="origin-track"><i style={{ width: `${(count / countryCounts[0][1]) * 100}%` }} /></div><strong>{count}</strong></div>)}</div><div className="surface-summary"><div><span>Highest risk region</span><strong>South Asia</strong></div><div><span>Geo-velocity flags</span><strong className="danger-text">04</strong></div></div></div></section>
          <section className="panel incidents-panel"><div className="panel-heading incidents-heading"><div><div className="panel-kicker"><ShieldAlert size={14} /> EVENT STREAM</div><h2>Live incident log</h2><p>Prioritized signals from the CanaryGate proxy and deception layer.</p></div><div className="export-actions">{isAdmin ? <><button className="export-button" onClick={exportCsv}><Download size={14} />CSV</button><button className="export-button" onClick={exportJson}><FileJson size={14} />JSON</button><button className="export-button" onClick={printPdf}><FileText size={14} />PDF</button></> : <span className="locked-label"><Lock size={13} /> Admin exports only</span>}</div></div><div className="filter-row"><div className="search-box"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IP, technique, or event..." /></div><div className="filter-select"><SlidersHorizontal size={14} /><select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}><option>All events</option><option>CANARY_TRIGGERED</option><option>BLOCKED_HIGH_RISK</option><option>ALLOWED_WITH_WARNING</option></select></div><select className="filter-select plain" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><span className="filter-count">{filteredIncidents.length} of {incidents.length} signals</span></div><div className="table-scroll"><table><thead><tr><th>Event</th><th>Source / origin</th><th>Severity</th><th>Technique</th><th>Review</th><th aria-label="Open details" /></tr></thead><tbody>{filteredIncidents.map((incident) => <tr key={incident.id} onClick={() => setSelected(incident)}><td><div className="event-cell"><span className={`event-indicator ${incident.severity.toLowerCase()}`} /><div><strong>{incident.incidentType.replaceAll("_", " ")}</strong><span>#{incident.id} · {formatTime(incident.timestamp)}</span></div></div></td><td><div className="source-cell"><strong>{incident.sourceIp}</strong><span>{incident.country}</span></div></td><td><span className={`severity ${incident.severity.toLowerCase()}`}>{incident.severity}</span></td><td><code>{incident.mitreTechnique}</code></td><td><span className={`review-status ${incident.reviewStatus}`}><i />{statusLabel(incident.reviewStatus)}</span></td><td><ChevronRight size={16} className="row-arrow" /></td></tr>)}</tbody></table>{filteredIncidents.length === 0 && <div className="empty-state"><Search size={22} /><strong>No signals match those filters.</strong><span>Try clearing the search or selecting a wider event scope.</span></div>}</div></section>
          <section className="bottom-grid"><div className="panel correlation-panel"><div className="panel-heading"><div><div className="panel-kicker"><Sparkles size={14} /> AI CORRELATION ENGINE</div><h2>High-priority patterns</h2></div><span className="status-badge"><CircleDot size={12} />{correlated.length} active</span></div>{correlated.length ? correlated.map((item) => <div className="correlation-row" key={item.sourceIp}><div className="correlation-icon"><AlertTriangle size={16} /></div><div><strong>{item.count} signals from {item.sourceIp}</strong><span>{item.country} · correlated within 5 minutes · elevated priority</span></div><ChevronRight size={16} /></div>) : <div className="empty-inline"><CheckCircle2 size={18} />No correlated multi-alert patterns detected.</div>}</div><div className="panel activity-panel"><div className="panel-heading"><div><div className="panel-kicker"><Timer size={14} /> ACTIVITY</div><h2>Recent actions</h2></div><button className="link-button">View all <ChevronRight size={14} /></button></div><div className="activity-list"><div><span className="activity-icon teal"><Check size={14} /></span><p><strong>Proxy heartbeat received</strong><span>18 seconds ago · system</span></p></div><div><span className="activity-icon purple"><UserRound size={14} /></span><p><strong>Analyst session started</strong><span>4 minutes ago · {session.username}</span></p></div><div><span className="activity-icon orange"><FileText size={14} /></span><p><strong>Review queue recalculated</strong><span>11 minutes ago · correlation engine</span></p></div></div></div></section>
        </div>
      </main>
      {selected && <div className="drawer-backdrop" onClick={() => setSelected(null)}><aside className="detail-drawer" onClick={(event) => event.stopPropagation()}><div className="drawer-top"><div><div className="panel-kicker">INCIDENT DETAIL</div><h2>#{selected.id} / {selected.incidentType.replaceAll("_", " ")}</h2></div><button className="icon-button" onClick={() => setSelected(null)}><X size={17} /></button></div><div className={`drawer-severity ${selected.severity.toLowerCase()}`}><span className="event-indicator" />{selected.severity} severity <span>·</span> {formatTime(selected.timestamp)}</div><div className="detail-list"><div><span>Source IP</span><strong>{selected.sourceIp}</strong></div><div><span>Origin</span><strong>{selected.country}</strong></div><div><span>MITRE ATT&CK</span><strong>{selected.mitreTechnique}</strong></div><div><span>Current review</span><strong>{statusLabel(selected.reviewStatus)}</strong></div></div><div className="detail-description"><div className="panel-kicker"><Sparkles size={13} /> AI EXPLANATION</div><p>{selected.details}</p><p className="detail-note">CanaryGate combined identity type, request rate, time-of-day, IP trust, geographic consistency, and behavioral history to produce this alert.</p></div><div className="drawer-actions"><span className="panel-kicker">UPDATE REVIEW STATUS</span>{isAdmin ? <div className="status-buttons"><button className={selected.reviewStatus === "confirmed" ? "selected" : ""} onClick={() => updateIncident(selected.id, "confirmed")}><CheckCircle2 size={15} />Confirmed</button><button className={selected.reviewStatus === "false_positive" ? "selected" : ""} onClick={() => updateIncident(selected.id, "false_positive")}><XCircle size={15} />False positive</button><button className={selected.reviewStatus === "unreviewed" ? "selected" : ""} onClick={() => updateIncident(selected.id, "unreviewed")}><CircleDot size={15} />Reset</button></div> : <div className="drawer-locked"><Lock size={15} />Sign in as Admin to update this incident.</div>}</div></aside></div>}
      {toast && <div className="toast"><CheckCircle2 size={16} />{toast}</div>}
    </div>
  );
}
