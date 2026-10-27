import { useState, useEffect, useMemo } from 'react';
import { Shield, ShieldAlert, Play, RotateCcw, Search, Download, Activity, AlertTriangle } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || '';
const HOSTS = ['127.0.0.1', 'localhost'];
const RANGES = [[1, 100, 'Quick 1-100'], [80, 443, 'Web 80-443'], [1, 1024, 'Well-known 1-1024']];

function validate(target, s, e) {
  const t = target.trim();
  if (!t) return 'Enter a target host or IPv4 address.';
  if (t.includes('://') || /[\s/]/.test(t)) return 'Use only a hostname or IP, with no scheme, spaces or slashes.';
  if (!Number.isInteger(s) || !Number.isInteger(e)) return 'Ports must be whole numbers.';
  if (s < 1 || e > 65535 || s > e) return 'Ports must be 1-65535 and start must not exceed end.';
  if (e - s + 1 > 2000) return 'Maximum 2,000 ports per scan.';
  return '';
}

function save(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

export default function App() {
  const [api, setApi] = useState('checking');
  const [target, setTarget] = useState('127.0.0.1');
  const [start, setStart] = useState('1');
  const [end, setEnd] = useState('100');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [scan, setScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [filter, setFilter] = useState('open');
  const [q, setQ] = useState('');

  useEffect(() => {
    const ping = () =>
      fetch(`${API}/api/health`).then((r) => setApi(r.ok ? 'online' : 'offline')).catch(() => setApi('offline'));
    ping();
    const id = setInterval(ping, 15000);
    return () => clearInterval(id);
  }, []);

  const run = async (e) => {
    e.preventDefault();
    const s = parseInt(start, 10), en = parseInt(end, 10);
    const err = validate(target, s, en);
    setError(err);
    if (err) return;
    setBusy(true);
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), start_port: s, end_port: en }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.detail || 'Scan failed.');
      data.finishedAt = new Date().toLocaleTimeString();
      setScan(data);
      setHistory((h) => [data, ...h].slice(0, 5));
      setFilter(data.open_ports > 0 ? 'open' : 'all');
      setApi('online');
    } catch (ex) {
      setError(ex instanceof TypeError ? 'Cannot reach the backend. Is FastAPI running on port 8000?' : ex.message);
      if (ex instanceof TypeError) setApi('offline');
    } finally {
      setBusy(false);
    }
  };

  const rows = useMemo(() => {
    if (!scan) return [];
    const k = q.trim().toLowerCase();
    return scan.results.filter(
      (r) =>
        (filter === 'all' || r.status === filter) &&
        (!k || String(r.port).includes(k) || r.service.toLowerCase().includes(k))
    );
  }, [scan, filter, q]);

  const csv = () =>
    save(
      `scan-${scan.target}.csv`,
      'port,status,service,response_time_ms\n' +
        scan.results.map((r) => [r.port, r.status, `"${r.service}"`, r.response_time_ms ?? ''].join(',')).join('\n'),
      'text/csv'
    );

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <Shield size={22} />
          <div>
            <b>PortScope</b>
            <span>TCP port scanner</span>
          </div>
        </div>

        <form onSubmit={run} className="form">
          <label>Target</label>
          <input value={target} onChange={(e) => setTarget(e.target.value)} disabled={busy} placeholder="127.0.0.1" autoComplete="off" />
          <div className="chips">
            {HOSTS.map((h) => (
              <button type="button" key={h} onClick={() => setTarget(h)} disabled={busy}>{h}</button>
            ))}
          </div>

          <label>Port range</label>
          <div className="pair">
            <input type="number" min="1" max="65535" value={start} onChange={(e) => setStart(e.target.value)} disabled={busy} />
            <span>to</span>
            <input type="number" min="1" max="65535" value={end} onChange={(e) => setEnd(e.target.value)} disabled={busy} />
          </div>
          <div className="chips">
            {RANGES.map(([a, b, n]) => (
              <button type="button" key={n} onClick={() => { setStart(String(a)); setEnd(String(b)); }} disabled={busy}>{n}</button>
            ))}
          </div>

          {error && <div className="err"><AlertTriangle size={15} />{error}</div>}

          <button className="go" disabled={busy}>
            <Play size={16} /> {busy ? 'Scanning…' : 'Start scan'}
          </button>
          <button type="button" className="ghost" disabled={busy} onClick={() => { setScan(null); setError(''); setQ(''); }}>
            <RotateCcw size={15} /> Clear results
          </button>
        </form>

        <div className="notice">
          <ShieldAlert size={18} />
          <p><b>Authorized use only.</b> Scan only systems you own or have written permission to test. Max 2,000 ports per scan.</p>
        </div>
        <div className={`api ${busy ? 'busy' : api}`}>
          <i /> {busy ? 'Scan in progress' : api === 'online' ? 'API online' : api === 'offline' ? 'API offline' : 'Checking API…'}
        </div>
      </aside>

      <main className="main">
        <header className="top">
          <h1>Scan dashboard</h1>
          <p>Connect-scan a host, see exposure at a glance, export the evidence.</p>
        </header>

        {busy && <div className="bar"><i /></div>}

        {!scan && !busy && (
          <div className="empty">
            <Activity size={34} />
            <h3>No scan yet</h3>
            <p>Pick a target and port range on the left, then press <b>Start scan</b>. Try 127.0.0.1 with 1-100 to begin.</p>
          </div>
        )}

        {scan && (
          <>
            <section className="stats">
              <div><span>Target</span><b className="sm">{scan.target}</b><em>{scan.ip_address}</em></div>
              <div><span>Scanned</span><b>{scan.ports_scanned}</b><em>ports</em></div>
              <div className="open"><span>Open</span><b>{scan.open_ports}</b><em>{((scan.open_ports / scan.ports_scanned) * 100).toFixed(1)}% of range</em></div>
              <div><span>Closed / filtered</span><b>{scan.closed_ports}</b><em>no handshake</em></div>
              <div><span>Duration</span><b>{scan.duration}s</b><em>finished {scan.finishedAt}</em></div>
            </section>

            <section className="card">
              <div className="head"><h3>Port map</h3><span>Each square is one port: green = open</span></div>
              <div className="map">
                {scan.results.map((r) => (
                  <i key={r.port} className={r.status} title={`${r.port} · ${r.status} · ${r.service}`} />
                ))}
              </div>
            </section>

            <section className="card">
              <div className="head">
                <h3>Results <small>{rows.length} of {scan.results.length}</small></h3>
                <div className="tools">
                  <div className="tabs">
                    {['open', 'closed', 'all'].map((f) => (
                      <button key={f} className={filter === f ? 'on' : ''} onClick={() => setFilter(f)}>{f}</button>
                    ))}
                  </div>
                  <div className="search"><Search size={14} /><input placeholder="Port or service" value={q} onChange={(e) => setQ(e.target.value)} /></div>
                  <button className="ghost sm" onClick={csv}><Download size={14} /> CSV</button>
                  <button className="ghost sm" onClick={() => save(`scan-${scan.target}.json`, JSON.stringify(scan, null, 2), 'application/json')}><Download size={14} /> JSON</button>
                </div>
              </div>
              <div className="scroll">
                <table>
                  <thead><tr><th>Port</th><th>Status</th><th>Likely service</th><th>RTT</th></tr></thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.port}>
                        <td className="mono">{r.port}</td>
                        <td><span className={`pill ${r.status}`}>{r.status}</span></td>
                        <td>{r.service}</td>
                        <td className="mono">{r.response_time_ms != null ? `${r.response_time_ms} ms` : '—'}</td>
                      </tr>
                    ))}
                    {!rows.length && <tr><td colSpan="4" className="none">Nothing matches this filter.</td></tr>}
                  </tbody>
                </table>
              </div>
              <p className="foot">Service names are common IANA defaults, not confirmed fingerprints.</p>
            </section>
          </>
        )}

        {history.length > 1 && (
          <section className="card">
            <div className="head"><h3>Recent scans</h3><span>This session</span></div>
            <div className="hist">
              {history.map((h, i) => (
                <button key={i} onClick={() => setScan(h)} className={h === scan ? 'on' : ''}>
                  <b>{h.target}</b><span>{h.open_ports} open · {h.ports_scanned} ports · {h.finishedAt}</span>
                </button>
              ))}
            </div>
          </section>
        )}

        <details className="card learn">
          <summary>How a TCP connect scan works</summary>
          <p>The engine opens a TCP socket to each port with a short timeout. If the three-way handshake (SYN, SYN-ACK, ACK) completes, the port is <b>open</b>. A reset or no reply is reported as <b>closed</b>. Workers are capped at 50, ranges at 2,000 ports, and no shell commands are ever run.</p>
        </details>
      </main>
    </div>
  );
}
