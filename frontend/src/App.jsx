
import { useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Command,
  FileSearch,
  Filter,
  Gauge,
  Globe2,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Network,
  RefreshCw,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Users,
  X,
  Zap,
} from 'lucide-react'

const activityBars = [30, 44, 35, 61, 48, 74, 46, 58, 39, 84, 52, 68, 45, 92, 60, 74, 43, 64, 35, 80, 55, 70, 48, 88, 58, 72, 40, 62, 35, 77, 51, 67, 42, 94, 61, 76, 46, 65, 38, 83, 54, 72, 45, 60, 36, 80, 52, 69]
const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000')
  .replace(/\/+$/, '')

function MetricCard({ label, value, note, icon: Icon, accent, trend }) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <span className="metric-label">{label}</span>
        <span className={`metric-icon ${accent}`}><Icon size={18} /></span>
      </div>
      <div className="metric-value-row">
        <strong>{value}</strong>
        {trend && <span className="metric-trend"><ArrowUpRight size={13} /> {trend}</span>}
      </div>
      <div className="metric-note">{note}</div>
    </div>
  )
}

function App() {
  const [activeNav, setActiveNav] = useState('Overview')
  const [alerts, setAlerts] = useState([])
  const [filter, setFilter] = useState('All')
  const [search, setSearch] = useState('')
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [mobileNav, setMobileNav] = useState(false)
  const [running, setRunning] = useState(false)
  const [aiReport, setAiReport] = useState(
    'Run an analysis to load the AI investigation report from your local SOC backend.',
  )
  const [apiStatus, setApiStatus] = useState('Demo data')
  const [eventsCount, setEventsCount] = useState(0)
  const [alertCount, setAlertCount] = useState(0)
  const [lastRun, setLastRun] = useState('Not connected yet')
  const [inputMode, setInputMode] = useState('sample')
  const [scenario, setScenario] = useState('normal')
  const [failedAttempts, setFailedAttempts] = useState(5)
  const [sourceIp, setSourceIp] = useState('192.0.2.10')
  const [intervalMinutes, setIntervalMinutes] = useState(5)
  const [includeSuccess, setIncludeSuccess] = useState(false)
  const [useAi, setUseAi] = useState(false)
  const [previewLines, setPreviewLines] = useState([])
  const [uploadFile, setUploadFile] = useState(null)
  const [analysisData, setAnalysisData] = useState(null)
  const [previousSummary, setPreviousSummary] = useState(null)
  const [errorMessage, setErrorMessage] = useState('')

  const visibleAlerts = alerts.filter((alert) => {
    const matchesFilter = filter === 'All' || alert.severity === filter
    const matchesSearch = `${alert.id} ${alert.title} ${alert.source} ${alert.target}`
      .toLowerCase()
      .includes(search.toLowerCase())
    return matchesFilter && matchesSearch
  })

  function customPayload() {
    return {
      mode: 'custom',
      failed_attempts: Number(failedAttempts),
      source_ip: sourceIp,
      interval_minutes: Number(intervalMinutes),
      include_success: includeSuccess,
      use_ai: useAi,
    }
  }

  async function requestJson(url, options) {
    const response = await fetch(url, options)
    const data = await response.json()
    if (!response.ok) throw new Error(data.detail || `Backend returned HTTP ${response.status}`)
    return data
  }

  async function runAnalysis() {
    setRunning(true)
    setErrorMessage('')
    try {
      let data
      if (inputMode === 'upload') {
        if (!uploadFile) throw new Error('Choose a .log file to upload.')
        if (!uploadFile.name.toLowerCase().endsWith('.log')) throw new Error('Only .log files are allowed.')
        if (uploadFile.size > 1024 * 1024) throw new Error('Log files must be 1 MiB or smaller.')
        data = await requestJson(`${apiBaseUrl}/api/analyze/upload?filename=${encodeURIComponent(uploadFile.name)}&use_ai=${useAi}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: uploadFile,
        })
      } else if (inputMode === 'custom') {
        data = await requestJson(`${apiBaseUrl}/api/analyze`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(customPayload()),
        })
      } else {
        data = await requestJson(`${apiBaseUrl}/api/analyze`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: inputMode, scenario, use_ai: useAi }),
        })
      }

      const detected = data.alerts ?? []
      if (analysisData) {
        setPreviousSummary({
          events: analysisData.events_processed,
          alerts: analysisData.alerts_generated,
          origin: analysisData.data_origin,
        })
      }

      setAnalysisData(data)
      setEventsCount(data.events_processed ?? 0)
      setAlertCount(data.alerts_generated ?? detected.length)
      setApiStatus('Connected')
      setLastRun(new Date().toLocaleTimeString())
      setAlerts(
        detected.map((alert, index) => ({
          id: alert.rule_id ?? `SF-${index + 1}`,
          title: (alert.alert_type ?? 'Security alert').replaceAll('_', ' '),
          source: alert.source_ip ?? 'Unknown',
          target: (alert.usernames ?? []).join(', ') || 'Linux authentication',
          severity: alert.severity
            ? alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)
            : 'Info',
          attempts: alert.failed_attempts ?? 0,
          time: alert.last_seen
            ? new Date(alert.last_seen).toLocaleTimeString()
            : 'Just now',
          status: 'Investigating',
          raw: alert,
        })),
      )

      if (detected.length > 0) {
        setSelectedAlert({
          id: detected[0].rule_id,
          title: detected[0].alert_type,
          source: detected[0].source_ip,
          target: (detected[0].usernames ?? []).join(', '),
          severity: detected[0].severity,
          attempts: detected[0].failed_attempts,
          time: detected[0].last_seen,
          status: 'Investigating',
          raw: detected[0],
        })
        setAiReport(
          detected[0].ai_investigation ||
          (detected[0].ai_investigation_error
            ? `AI unavailable: ${detected[0].ai_investigation_error}\n\nDetection results are still available below.`
            : 'AI investigation was not requested. Detection results are available below.'),
        )
      } else {
        setSelectedAlert(null)
        setAiReport(data.ai_enabled
          ? 'Analysis completed. No alerts were detected in this input.'
          : 'AI investigation was not requested. Detection results are available below.')
      }
    } catch (error) {
      setApiStatus('Offline')
      setErrorMessage(error.message)
    } finally {
      setRunning(false)
    }
  }

  async function previewCustomLogs() {
    setErrorMessage('')
    try {
      const data = await requestJson(`${apiBaseUrl}/api/logs/preview`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(customPayload()),
      })
      setPreviewLines(data.lines)
    } catch (error) {
      setErrorMessage(error.message)
    }
  }

  return (
    <div className="app-shell">
      {mobileNav && <button className="mobile-scrim" onClick={() => setMobileNav(false)} aria-label="Close navigation" />}
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={23} strokeWidth={2.2} /></div>
          <div>
            <div className="brand-name">SENTINEL<span>FORGE</span></div>
            <div className="brand-caption">SECURITY OPERATIONS</div>
          </div>
          <button className="mobile-close icon-button" onClick={() => setMobileNav(false)} aria-label="Close menu"><X size={18} /></button>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <button className={`workspace-switch ${activeNav === 'Overview' ? 'workspace-active' : ''}`} onClick={() => setActiveNav('Overview')}>
          <div className="workspace-avatar"><Command size={17} /></div>
          <div className="workspace-copy"><strong>Personal SOC</strong><span>Local environment</span></div>
          <ChevronDown size={15} className="muted-icon" />
        </button>

        <div className="nav-section-label">OPERATIONS</div>
        <nav className="nav-list">
          {[
            { label: 'Overview', icon: LayoutDashboard },
            { label: 'Alerts', icon: ShieldAlert, count: String(alertCount) },
            { label: 'Event explorer', icon: FileSearch },
            { label: 'Network activity', icon: Network },
          ].map(({ label, icon: Icon, count }) => (
            <button key={label} className={`nav-item ${activeNav === label ? 'nav-active' : ''}`} onClick={() => { setActiveNav(label); setMobileNav(false) }}>
              <Icon size={17} /><span>{label}</span>{count && <span className="nav-count">{count}</span>}
            </button>
          ))}
        </nav>

        <div className="nav-section-label">INVESTIGATE</div>
        <nav className="nav-list">
          {[
            { label: 'AI investigations', icon: BrainCircuit },
            { label: 'Log sources', icon: Server },
            { label: 'Identity & access', icon: Users },
          ].map(({ label, icon: Icon }) => (
            <button key={label} className={`nav-item ${activeNav === label ? 'nav-active' : ''}`} onClick={() => { setActiveNav(label); setMobileNav(false) }}>
              <Icon size={17} /><span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="plan-card">
            <div className="plan-icon"><Zap size={16} /></div>
            <div className="plan-title">Local AI engine</div>
            <div className="plan-description">Powered by Ollama · llama3.2:3b</div>
            <div className="plan-status"><span className="status-dot" /> Runs on your machine</div>
          </div>
          <button className={`nav-item ${activeNav === 'Settings' ? 'nav-active' : ''}`} onClick={() => setActiveNav('Settings')}><Settings2 size={17} /><span>Settings</span></button>
          <div className="profile-row">
            <div className="profile-avatar">SF</div>
            <div className="profile-copy"><strong>SOC Analyst</strong><span>Local administrator</span></div>
            <MoreHorizontal size={18} className="muted-icon" />
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs">
            <button className="mobile-menu icon-button" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={20} /></button>
            <span>Workspace</span><span className="crumb-separator">/</span><strong>{activeNav}</strong>
          </div>
          <div className="topbar-actions">
            <div className={`connection-pill ${apiStatus === 'Connected' ? 'connected' : apiStatus === 'Offline' ? 'offline' : ''}`}><span className="status-dot" />{apiStatus}</div>
            <button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><span /></button>
            <div className="topbar-divider" />
            <div className="avatar-small">SF</div>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS CENTER</div>
              <h1>{activeNav === 'Overview' ? 'Security overview' : activeNav}</h1>
              <p>Monitor your environment, investigate threats, and turn signals into action.</p>
            </div>
            <div className="heading-actions">
              <button className="button-secondary" onClick={() => { setFilter('All'); setSearch('') }}><RefreshCw size={15} /> Reset filters</button>
            </div>
          </section>

          <section className="environment-strip">
            <div className="environment-left"><span className="environment-icon"><ShieldCheck size={16} /></span><span><strong>Environment health</strong><span className="env-subtitle">Local analysis pipeline</span></span></div>
            <div className="environment-item"><span className="status-dot" /><span>Detection engine <strong>Ready</strong></span></div>
            <div className="environment-item"><span className="status-dot" /><span>AI agent <strong>Local model</strong></span></div>
            <div className="environment-right"><Clock3 size={14} /> Last run: {lastRun}</div>
          </section>

          <section className="metric-grid">
            <MetricCard label="Events processed" value={eventsCount.toLocaleString()} note="Normalized authentication events" icon={Activity} accent="accent-cyan" trend="Live" />
            <MetricCard label="Alerts generated" value={alertCount.toLocaleString()} note="Detections from current analysis" icon={ShieldAlert} accent="accent-red" />
            <MetricCard label="High severity" value={alerts.filter((alert) => alert.severity === 'High').length.toLocaleString()} note="Require analyst review" icon={AlertTriangle} accent="accent-amber" />
            <MetricCard label="AI investigations" value={alerts.filter((alert) => alert.raw?.ai_investigation).length.toLocaleString()} note="Reports returned by local AI" icon={BrainCircuit} accent="accent-violet" />
          </section>

          <section className="panel lab-panel">
            <div className="panel-heading"><div><span className="section-kicker">INPUT</span><h2>Interactive log analysis</h2><p>Choose a source and run the existing Linux authentication pipeline.</p></div><span className={`origin-badge ${analysisData?.data_origin === 'uploaded' ? 'uploaded' : ''}`}>{analysisData?.data_origin === 'uploaded' ? 'UPLOADED DATA' : 'SYNTHETIC DEMO'}</span></div>
            <div className="lab-mode-tabs" aria-label="Log input mode">
              {[['sample', 'Sample log'], ['scenario', 'Scenarios'], ['custom', 'Custom builder'], ['upload', 'Upload log']].map(([mode, label]) => <button key={mode} className={inputMode === mode ? 'active' : ''} onClick={() => { setInputMode(mode); setErrorMessage('') }}>{label}</button>)}
            </div>
            {inputMode === 'sample' && <p className="lab-hint">Uses the bundled Linux authentication demonstration log.</p>}
            {inputMode === 'scenario' && <div className="lab-form-row"><label>Scenario<select value={scenario} onChange={(event) => setScenario(event.target.value)}><option value="normal">Normal login activity</option><option value="failures">Repeated failed SSH logins</option><option value="success_after_failures">Failures followed by a successful login</option></select></label><p className="lab-hint">Scenarios are synthetic demonstrations. Analysis results come from the backend.</p></div>}
            {inputMode === 'custom' && <>
              <div className="lab-form-row">
                <label>Failed SSH attempts<input type="number" min="0" max="20" value={failedAttempts} onChange={(event) => setFailedAttempts(event.target.value)} /></label>
                <label>Source IP<select value={sourceIp} onChange={(event) => setSourceIp(event.target.value)}><option>192.0.2.10</option><option>198.51.100.25</option><option>203.0.113.50</option><option>10.0.0.10</option><option>192.168.1.50</option></select></label>
                <label>Time interval (minutes)<input type="number" min="1" max="30" value={intervalMinutes} onChange={(event) => setIntervalMinutes(event.target.value)} /></label>
                <label className="lab-checkbox"><input type="checkbox" checked={includeSuccess} onChange={(event) => setIncludeSuccess(event.target.checked)} /> Include successful login</label>
              </div>
              <div className="lab-inline-actions"><button className="button-secondary" onClick={previewCustomLogs}>Preview generated lines</button><span>Synthetic lines parsed by the backend.</span></div>
              {previewLines.length > 0 && <pre className="log-preview">{previewLines.join('\n')}</pre>}
            </>}
            {inputMode === 'upload' && <div className="lab-upload"><label>Select Linux auth log (.log, max 1 MiB)<input type="file" accept=".log,text/plain" onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)} /></label><span>{uploadFile ? `${uploadFile.name} · ${(uploadFile.size / 1024).toFixed(1)} KiB` : 'File is analyzed in memory and not saved to disk.'}</span></div>}
            <div className="lab-run-row"><span className="section-kicker">ANALYSIS</span><label className="lab-checkbox"><input type="checkbox" checked={useAi} onChange={(event) => setUseAi(event.target.checked)} /> Optional AI report</label><button className="button-primary" onClick={runAnalysis} disabled={running}>{running ? 'Analyzing…' : 'Analyze input'}</button></div>
            {errorMessage && <div className="lab-error" role="alert">{errorMessage}</div>}
          </section>

          {analysisData && <section className="panel learning-panel">
            <div className="panel-heading"><div><span className="section-kicker">RESULTS</span><h2>Analysis evidence &amp; learning notes</h2><p>{analysisData.data_origin === 'uploaded' ? 'Uploaded log data' : analysisData.data_origin === 'sample' ? 'Bundled sample log' : 'Synthetic demonstration data'} · {analysisData.events_processed} parsed events · {analysisData.alerts_generated} alerts{analysisData.ignored_lines > 0 ? ` · ${analysisData.ignored_lines} ignored line(s)` : ''}</p></div><span className={`origin-badge ${analysisData.data_origin === 'uploaded' ? 'uploaded' : ''}`}>{analysisData.data_origin === 'uploaded' ? 'UPLOADED' : analysisData.data_origin === 'sample' ? 'SAMPLE' : 'SYNTHETIC'}</span></div>
            {previousSummary && <div className="comparison-note"><strong>Before / after</strong><span>Previous: {previousSummary.events} events, {previousSummary.alerts} alerts ({previousSummary.origin})</span><ArrowDownRight size={15} /><span>Current: {analysisData.events_processed} events, {analysisData.alerts_generated} alerts ({analysisData.data_origin})</span></div>}
            <div className="rule-explainer"><strong>Rule SF-SSH-001</strong><span>{analysisData.rule_explanation?.summary ?? 'At least 5 failed SSH logins from one source IP within 5 minutes trigger a high severity alert.'}</span></div>
            {analysisData.alerts.length === 0 && <div className="rule-outcome"><strong>No alert triggered.</strong><span>The detection engine found no source IP with 5 failed SSH logins in one 5-minute window. Observed failed-login evidence by source:</span>{analysisData.failed_event_summary.length === 0 ? <span> None in the parsed events.</span> : analysisData.failed_event_summary.map((summary) => <span key={summary.source_ip}><code>{summary.source_ip}</code>: {summary.failed_attempts} total; maximum in any 5-minute window: {summary.maximum_in_five_minute_window} ({new Date(summary.first_seen).toLocaleTimeString()}–{new Date(summary.last_seen).toLocaleTimeString()}).</span>)}<span>This is an absence of a matching pattern in the parsed input, not proof that the system is safe.</span></div>}
            {analysisData.alerts.map((alert) => {
              const relatedEvents = analysisData.events.filter((event) => event.source_ip === alert.source_ip && event.timestamp >= alert.first_seen && event.timestamp <= alert.last_seen)
              const evidence = relatedEvents.filter((event) => event.event_type === 'ssh_login_failed')
              return <div className="evidence-card" key={`${alert.rule_id}-${alert.source_ip}`}>
                <div className="evidence-heading"><strong>{alert.alert_type.replaceAll('_', ' ')}</strong><span className={`severity-badge ${alert.severity.toLowerCase()}`}>{alert.severity}</span></div>
                <p><strong>Observed evidence:</strong> {evidence.length} failed SSH login event(s) from <code>{alert.source_ip}</code>, {new Date(alert.first_seen).toLocaleString()} – {new Date(alert.last_seen).toLocaleString()} ({alert.window_minutes}-minute rule window).</p>
                <p><strong>Possible interpretation:</strong> Repeated failures may indicate password guessing or misconfigured automation. They are suspicious evidence, not proof of a successful compromise. {relatedEvents.some((event) => event.event_type === 'ssh_login_success') ? 'A successful login is also visible in the same source time range; its relationship to the failures needs investigation.' : 'This alert alone does not establish that any login succeeded.'}</p>
                <div className="evidence-timeline">{relatedEvents.map((event, index) => <div key={`${event.timestamp}-${index}`}><time>{new Date(event.timestamp).toLocaleTimeString()}</time><span>{event.event_type.replaceAll('_', ' ')}</span><code>{event.username} · {event.source_ip}</code></div>)}</div>
              </div>
            })}
            <div className="event-timeline-heading">Parsed event timeline</div>
            <div className="evidence-timeline all-events">{analysisData.events.map((event, index) => <div key={`${event.timestamp}-${index}`}><time>{new Date(event.timestamp).toLocaleString()}</time><span>{event.event_type.replaceAll('_', ' ')}</span><code>{event.username} · {event.source_ip}</code></div>)}</div>
            {analysisData.alerts.some((alert) => alert.ai_investigation_error) && <p className="ai-unavailable">AI unavailable: {analysisData.alerts.find((alert) => alert.ai_investigation_error).ai_investigation_error} Detection results remain available.</p>}
          </section>}

          <section className="dashboard-grid">
            <div className="panel activity-panel">
              <div className="panel-heading">
                <div><h2>Event activity</h2><p>Authentication event volume · illustrative view</p></div>
                <button className="select-button">Last 24 hours <ChevronDown size={14} /></button>
              </div>
              <div className="chart-legend"><span><i className="legend-cyan" /> Auth events</span><span><i className="legend-red" /> Failed logins</span><span className="chart-total"><strong>{eventsCount}</strong> events loaded</span></div>
              <div className="bar-chart" aria-label="Illustrative event activity chart">
                {activityBars.map((height, index) => <div key={index} className="bar-group"><span className={`bar ${index % 7 === 3 ? 'bar-alert' : ''}`} style={{ height: `${height}%` }} /></div>)}
              </div>
              <div className="chart-axis"><span>00:00</span><span>04:00</span><span>08:00</span><span>12:00</span><span>16:00</span><span>20:00</span><span>Now</span></div>
              <div className="chart-footnote"><span className="info-dot">i</span> Chart pattern is illustrative; live event time-series aggregation is not implemented yet.</div>
            </div>

            <div className="panel severity-panel">
              <div className="panel-heading"><div><h2>Alert severity</h2><p>Current analysis results</p></div><button className="icon-button" aria-label="More options"><MoreHorizontal size={18} /></button></div>
              <div className="severity-ring-wrap">
                <div className="severity-ring"><div className="ring-center"><strong>{alerts.filter((alert) => alert.severity !== 'Info').length}</strong><span>Alerts</span></div></div>
              </div>
              <div className="severity-legend">
                <div><span className="severity-key key-high" /><span>High</span><strong>{alerts.filter((alert) => alert.severity === 'High').length}</strong></div>
                <div><span className="severity-key key-medium" /><span>Medium</span><strong>{alerts.filter((alert) => alert.severity === 'Medium').length}</strong></div>
                <div><span className="severity-key key-low" /><span>Low / Info</span><strong>{alerts.filter((alert) => ['Low', 'Info'].includes(alert.severity)).length}</strong></div>
              </div>
              <div className="severity-foot"><span className="status-dot" /> Updated from current dashboard state</div>
            </div>
          </section>

          <section className="panel alerts-panel">
            <div className="panel-heading alerts-heading">
              <div><div className="title-inline"><h2>Security alerts</h2><span className="count-badge">{alerts.length}</span></div><p>Detection findings from the latest log analysis</p></div>
              <div className="alert-controls">
                <div className="search-field"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search alerts…" /></div>
                <div className="filter-wrap"><Filter size={14} /><select value={filter} onChange={(event) => setFilter(event.target.value)} aria-label="Filter severity"><option value="All">All severity</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="Info">Info</option></select></div>
              </div>
            </div>
            <div className="table-scroll">
              <table className="alerts-table">
                <thead><tr><th>DETECTION</th><th>SOURCE IP</th><th>SEVERITY</th><th>EVENTS</th><th>LAST SEEN</th><th>STATUS</th><th /></tr></thead>
                <tbody>
                  {visibleAlerts.map((alert) => (
                    <tr key={alert.id} className={selectedAlert?.id === alert.id ? 'selected-row' : ''} onClick={() => { setSelectedAlert(alert); if (alert.raw?.ai_investigation) setAiReport(alert.raw.ai_investigation) }} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') setSelectedAlert(alert) }}>
                      <td><div className="detection-cell"><span className={`detection-icon ${alert.severity.toLowerCase()}`}><ShieldAlert size={16} /></span><div><strong>{alert.title}</strong><span>{alert.id}</span></div></div></td>
                      <td className="ip-cell">{alert.source}</td>
                      <td><span className={`severity-badge ${alert.severity.toLowerCase()}`}>{alert.severity}</span></td>
                      <td className="attempt-cell">{alert.attempts}</td>
                      <td className="time-cell">{alert.time}</td>
                      <td><span className={`status-label ${alert.status.toLowerCase()}`}><i />{alert.status}</span></td>
                      <td><button className="row-action" aria-label={`Select ${alert.id}`} onClick={(event) => { event.stopPropagation(); setSelectedAlert(alert); if (alert.raw?.ai_investigation) setAiReport(alert.raw.ai_investigation) }}><MoreHorizontal size={17} /></button></td>
                    </tr>
                  ))}
                  {visibleAlerts.length === 0 && <tr><td colSpan="7" className="empty-state">No alerts match your search or severity filter.</td></tr>}
                </tbody>
              </table>
            </div>
            <div className="table-footer"><span>Showing <strong>{visibleAlerts.length}</strong> of <strong>{alerts.length}</strong> records</span><span>Detection rules · SF series</span></div>
          </section>

          <section className="bottom-grid">
            <div className="panel ai-panel">
              <div className="panel-heading"><div className="ai-heading"><span className="ai-mark"><BrainCircuit size={19} /></span><div><h2>AI investigation</h2><p>Local LLM · evidence-grounded analysis</p></div></div><span className="local-badge"><span className="status-dot" /> LOCAL</span></div>
              <div className="ai-context">
                <div><span className="context-label">SELECTED DETECTION</span><strong>{selectedAlert?.title ?? 'No alert selected'}</strong></div>
                <div><span className="context-label">SOURCE ADDRESS</span><strong className="ip-cell">{selectedAlert?.source ?? '—'}</strong></div>
                <div><span className="context-label">SEVERITY</span><span className={`severity-badge ${(selectedAlert?.severity ?? 'info').toLowerCase()}`}>{selectedAlert?.severity ?? 'Info'}</span></div>
              </div>
              <div className="ai-report">
                <div className="report-top"><span><span className="report-pulse" /> INVESTIGATION REPORT</span><button className="icon-button" onClick={() => navigator.clipboard?.writeText(aiReport)} aria-label="Copy report"><MoreHorizontal size={18} /></button></div>
                <pre>{aiReport}</pre>
              </div>
              <div className="ai-footer"><span><LockKeyhole size={14} /> Analysis runs locally when Ollama is available</span><button className="text-button" onClick={runAnalysis} disabled={running}>Re-run investigation <ArrowUpRight size={14} /></button></div>
            </div>

            <div className="panel sources-panel">
              <div className="panel-heading"><div><h2>Log sources</h2><p>Data available to the pipeline</p></div><button className="icon-button" aria-label="View sources"><MoreHorizontal size={18} /></button></div>
              <div className="source-item"><span className="source-icon"><Terminal size={17} /></span><div className="source-copy"><strong>Linux authentication</strong><span>SSH / sshd · sample log</span></div><span className="source-live"><i /> Loaded</span></div>
              <div className="source-item"><span className="source-icon"><Server size={17} /></span><div className="source-copy"><strong>Detection engine</strong><span>Rule SF-SSH-001</span></div><span className="source-live"><i /> Ready</span></div>
              <div className="source-item"><span className="source-icon"><BrainCircuit size={17} /></span><div className="source-copy"><strong>Ollama model</strong><span>llama3.2:3b</span></div><span className="source-live"><i /> Local</span></div>
              <div className="source-note"><Globe2 size={15} /><span>Sample data is synthetic. No external threat intelligence feed is connected in this build.</span></div>
              <button className="source-action" onClick={runAnalysis} disabled={running}>{running ? 'Running analysis…' : 'Analyze log source'} <ArrowDownRight size={15} /></button>
            </div>
          </section>

          <footer className="app-footer"><div><span className="footer-mark"><Shield size={13} /></span> SENTINELFORGE SOC <span className="footer-sep">/</span> <span>Security, with context.</span></div><div><span className="status-dot" /> Local development environment <span className="footer-sep">·</span> v1.0.0</div></footer>
        </div>
      </main>
    </div>
  )
}

export default App
