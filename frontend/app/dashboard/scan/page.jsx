'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import ReactMarkdown from 'react-markdown'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'

const supabaseRef = { current: null }

function getSupabase() {
  if (!supabaseRef.current) {
    let createBrowserClient
    try {
      createBrowserClient = require('@supabase/ssr').createBrowserClient
    } catch {
      return null
    }
    supabaseRef.current = createBrowserClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    )
  }
  return supabaseRef.current
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

async function startScan(token, target, scanMode) {
  const res = await fetch(`${API_URL}/api/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ target, scan_type: scanMode }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

async function pollScan(token, scanId) {
  const res = await fetch(`${API_URL}/api/scan/${scanId}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

async function analyzeScan(token, ports, cveFindings) {
  const res = await fetch(`${API_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ ports, cve_findings: cveFindings }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

function sanitize(markdown) {
  if (typeof window === 'undefined') return markdown
  try {
    const DOMPurify = require('dompurify')
    return DOMPurify.sanitize(markdown)
  } catch (_) {
    return markdown
  }
}

const scanMessages = [
  'Port sweep in progress...',
  'Service fingerprinting...',
  'Firewall detection active...',
  'CVE correlation running...',
]

const phaseColors = {
  queued: '#00ff88',
  scanning: '#4af4ff',
  analyzing: '#ffb340',
  complete: '#00ff88',
  failed: '#ff4560',
}

function formatCVSS(score) {
  if (score === null || score === undefined) return '—'
  return parseFloat(score).toFixed(1)
}

const sevColors = ['#ff4560', '#ffb340', '#4af4ff', 'rgba(240,237,232,0.35)']

function parseCvss(cvss) {
  if (cvss === null || cvss === undefined) return 0
  return parseFloat(cvss) || 0
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(10,10,15,0.95)',
      border: '1px solid rgba(255,255,255,0.1)',
      padding: '10px 14px',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '11px',
      color: '#f0ede8',
    }}>
      <p style={{ marginBottom: '4px', color: 'rgba(240,237,232,0.5)' }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color || p.payload.fill }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

export default function ScanPage() {
  const router = useRouter()
  const supabase = getSupabase()
  const logBodyRef = useRef(null)
  const pollIntervalRef = useRef(null)

  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState('fast')
  const [phase, setPhase] = useState('idle')
  const [logs, setLogs] = useState([])
  const [scanId, setScanId] = useState(null)
  const [error, setError] = useState(null)
  const [inputError, setInputError] = useState(null)
  const [activeTab, setActiveTab] = useState('report')
  const [pollCount, setPollCount] = useState(0)
  const [results, setResults] = useState(null)
  const [ports, setPorts] = useState([])
  const [cveFindings, setCveFindings] = useState([])

  useEffect(() => {
    if (logBodyRef.current) {
      logBodyRef.current.scrollTop = logBodyRef.current.scrollHeight
    }
  }, [logs])

  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current)
    }
  }, [])

  function addLog(tagType, tag, message) {
    const now = new Date()
    const time = [now.getHours(), now.getMinutes(), now.getSeconds()]
      .map((n) => String(n).padStart(2, '0')).join(':')
    setLogs((prev) => [...prev, { time, tagType, tag, message }])
  }

  function getProgress() {
    if (phase === 'queued') return 15
    if (phase === 'scanning') return 50
    if (phase === 'analyzing') return 85
    if (phase === 'complete') return 100
    if (phase === 'failed') return 100
    return 0
  }

  const privateIPRegex = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.0\.0\.1)/
  const validTarget = target.trim() && privateIPRegex.test(target.trim())

  function handleTargetChange(val) {
    setTarget(val)
    if (val && !privateIPRegex.test(val)) {
      setInputError('Only private IP ranges allowed — 10.x, 172.16.x, 192.168.x, 127.0.0.1')
    } else {
      setInputError(null)
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (inputError || !target.trim()) return

    const { data: { session } } = await getSupabase().auth.getSession()
    if (!session) {
      router.push('/login')
      return
    }
    const token = session.access_token
    const t = target.trim()

    setPhase('queued')
    setError(null)
    setResults(null)
    setPorts([])
    setCveFindings([])
    setLogs([])
    addLog('info', 'INIT', `Scan queued for ${t}`)
    addLog('info', 'MODE', `Profile: ${scanMode.toUpperCase()}`)

    let scanIdVal
    try {
      const data = await startScan(token, t, scanMode)
      scanIdVal = data.scan_id
      setScanId(scanIdVal)
      addLog('ok', 'QUEUE', `Job accepted — ID: ${scanIdVal.substring(0, 8)}...`)
    } catch (err) {
      setPhase('failed')
      addLog('err', 'ERR', err.message || 'Failed to queue scan')
      return
    }

    setPhase('scanning')
    addLog('info', 'SCAN', 'Nmap engine initializing...')

    let count = 0
    pollIntervalRef.current = setInterval(async () => {
      count++
      setPollCount(count)
      try {
        const res = await pollScan(token, scanIdVal)
        if (res.status === 'running') {
          // FIX: Stop looping infinitely. Only print the 4 sequence messages once.
          if (count <= scanMessages.length) {
            addLog('info', 'SCAN', scanMessages[count - 1])
          }
          if (count >= 40) {
            clearInterval(pollIntervalRef.current)
            setPhase('failed')
            addLog('err', 'TIMEOUT', 'Scan timed out after 2 minutes')
          }
        } else if (res.status === 'complete') {
          clearInterval(pollIntervalRef.current)
          
          const rawPorts = res.result_json?.ports
          const portData = Array.isArray(rawPorts) ? rawPorts : (rawPorts ? Object.values(rawPorts) : [])
          
          const rawCves = res.result_json?.cve_findings
          const cveData = Array.isArray(rawCves) ? rawCves : (rawCves ? Object.values(rawCves) : [])
          
          // FIX: Use cveData (which contains the top-level CVE array from the backend). 
          // If we must extract from ports fallback, look for 'p.cves', NOT 'p.cve_findings'
          const finalCves = cveData.length > 0 ? cveData : portData.flatMap((p) => p.cves || [])
          
          setPorts(portData)
          setCveFindings(finalCves)
          
          addLog('ok', 'DONE', `Scan complete — ${portData.length} ports found`)
          addLog('info', 'CVE', `${finalCves.length} CVEs correlated`)
          setPhase('analyzing')
        } else if (res.status === 'failed') {
          clearInterval(pollIntervalRef.current)
          setPhase('failed')
          addLog('err', 'FAIL', res.error_message || 'Scan failed')
        }
      } catch (err) {
        clearInterval(pollIntervalRef.current)
        setPhase('failed')
        addLog('err', 'ERR', err.message || 'Polling failed')
      }
    }, 3000)
  }

  useEffect(() => {
    if (phase !== 'analyzing' || !scanId) return
    const run = async () => {
      try {
        const { data: { session } } = await getSupabase().auth.getSession()
        if (!session) return
        const reportData = await analyzeScan(session.access_token, ports, cveFindings)
        addLog('ok', 'AI', 'Gemini analysis complete')
        setResults({ ai_summary: reportData.report, ports, cve_findings: cveFindings })
        setPhase('complete')
      } catch (err) {
        addLog('err', 'AI', err.message || 'Analysis failed')
        setPhase('complete')
      }
    }
    run()
  }, [phase])

  function handleNewScan() {
    setTarget('')
    setScanMode('fast')
    setPhase('idle')
    setLogs([])
    setScanId(null)
    setError(null)
    setInputError(null)
    setResults(null)
    setPorts([])
    setCveFindings([])
    setActiveTab('report')
  }

  function downloadJSON() {
    if (!results) return
    const blob = new Blob([JSON.stringify({ ports, cve_findings: cveFindings }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `netsec-scan-${scanId}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  function downloadReport() {
    if (!results?.ai_summary) return
    const blob = new Blob([results.ai_summary], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `netsec-report-${scanId}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  const sevData = (() => {
    const buckets = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    cveFindings.forEach((cve) => {
      const score = parseCvss(cve.cvss)
      if (score >= 9) buckets.Critical++
      else if (score >= 7) buckets.High++
      else if (score >= 4) buckets.Medium++
      else buckets.Low++
    })
    return Object.entries(buckets)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value }))
  })()

  const topCves = [...cveFindings]
    .sort((a, b) => parseCvss(b.cvss) - parseCvss(a.cvss))
    .slice(0, 5)
    .map((cve) => ({ id: cve.id || cve.cve_id || 'N/A', cvss: parseCvss(cve.cvss) }))

  const inputStyle = {
    width: '100%',
    background: 'rgba(255,255,255,0.04)',
    border: inputError ? '1px solid #ff4560' : '1px solid rgba(255,255,255,0.08)',
    padding: '14px 16px',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '12px',
    color: '#f0ede8',
    outline: 'none',
    transition: 'border-color 0.2s, box-shadow 0.2s',
  }

  const modeBtn = (mode, label) => ({
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.1em',
    padding: '10px 20px',
    border: scanMode === mode ? '1px solid #00ff88' : '1px solid rgba(255,255,255,0.08)',
    background: scanMode === mode ? 'rgba(0,255,136,0.05)' : 'transparent',
    color: scanMode === mode ? '#00ff88' : 'rgba(240,237,232,0.5)',
    cursor: 'pointer',
    transition: 'all 0.2s',
  })

  const tabBtn = (tab) => ({
    background: 'none',
    border: 'none',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '10px',
    letterSpacing: '0.15em',
    textTransform: 'uppercase',
    color: activeTab === tab ? '#f0ede8' : 'rgba(240,237,232,0.35)',
    padding: '0 0 10px',
    cursor: 'pointer',
    borderBottom: activeTab === tab ? '1px solid #00ff88' : '1px solid transparent',
    marginRight: '32px',
    transition: 'color 0.2s, border-color 0.2s',
  })

  return (
    <div>
      <style>{`
        @keyframes blink { 0%,100% { opacity:1 } 50% { opacity:0 } }
        @keyframes slideIn {
          from { opacity:0; transform:translateX(40px); }
          to   { opacity:1; transform:translateX(0); }
        }
        .results-panel { animation: slideIn 0.5s cubic-bezier(0.16,1,0.3,1) forwards; }
        .log-scroll::-webkit-scrollbar { width:4px; }
        .log-scroll::-webkit-scrollbar-track { background:transparent; }
        .log-scroll::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.1); border-radius:2px; }
        .prose-netsec h1 { font-family:'Syne',sans-serif; font-weight:600; font-size:24px; color:#f0ede8; margin:0 0 16px; }
        .prose-netsec h2 { font-family:'Syne',sans-serif; font-weight:600; font-size:18px; color:#f0ede8; margin:24px 0 12px; }
        .prose-netsec h3 { font-family:'Syne',sans-serif; font-weight:500; font-size:15px; color:#f0ede8; margin:20px 0 8px; }
        .prose-netsec p { font-family:'Instrument Sans',sans-serif; font-size:14px; color:rgba(240,237,232,0.7); line-height:1.7; margin:0 0 12px; }
        .prose-netsec code { font-family:'JetBrains Mono',monospace; font-size:12px; background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:2px; color:#00ff88; }
        .prose-netsec pre { background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.06); padding:16px; border-radius:4px; overflow:auto; margin:16px 0; }
        .prose-netsec pre code { background:none; padding:0; }
        .prose-netsec ul { list-style:none; padding:0; margin:0 0 12px; }
        .prose-netsec ul li { padding:6px 0 6px 20px; position:relative; font-family:'Instrument Sans',sans-serif; font-size:14px; color:rgba(240,237,232,0.7); }
        .prose-netsec ul li::before { content:'→'; position:absolute; left:0; color:#00ff88; font-family:'JetBrains Mono',monospace; }
        .prose-netsec strong { color:#00ff88; font-weight:600; }
        .prose-netsec blockquote { border-left:3px solid #ff4560; padding-left:16px; margin:16px 0; color:rgba(240,237,232,0.5); font-style:italic; }
        .port-card:hover { border-color:rgba(0,255,136,0.3) !important; }
      `}</style>

      {/* Header */}
      <div style={{ marginBottom: '36px' }}>
        <h1 style={{ fontFamily: "'Syne',sans-serif", fontWeight: 600, fontSize: '28px', color: '#f0ede8', marginBottom: '6px' }}>
          New Scan
        </h1>
        <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.35)', letterSpacing: '0.1em' }}>
          Run a network security scan on a private target
        </p>
      </div>

      {/* Two column layout */}
      <div style={{ display: 'flex', gap: '24px', alignItems: 'flex-start' }}>

        {/* LEFT — Form + Log */}
        <div style={{ width: phase === 'idle' || phase === 'failed' ? '100%' : '45%', transition: 'width 0.4s' }}>

          {/* Scan Form */}
          {(phase === 'idle' || phase === 'failed') && (
            <div style={{ marginBottom: '24px' }}>
              <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.18em', color: '#00ff88', marginBottom: '8px' }}>
                New Scan
              </p>
              <h2 style={{ fontFamily: "'Syne',sans-serif", fontWeight: 500, fontSize: '36px', color: '#f0ede8', marginBottom: '28px', lineHeight: 1.1 }}>
                Scan a target
              </h2>

              <form onSubmit={handleSubmit}>
                <div style={{ marginBottom: '20px' }}>
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => handleTargetChange(e.target.value)}
                    placeholder="192.168.1.1"
                    style={inputStyle}
                    onFocus={(e) => {
                      if (!inputError) {
                        e.target.style.borderColor = 'rgba(0,255,136,0.5)'
                        e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.06)'
                      }
                    }}
                    onBlur={(e) => {
                      e.target.style.borderColor = inputError ? '#ff4560' : 'rgba(255,255,255,0.08)'
                      e.target.style.boxShadow = 'none'
                    }}
                  />
                  <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '9px', color: 'rgba(240,237,232,0.25)', marginTop: '8px', letterSpacing: '0.05em' }}>
                    Private IP ranges only — 10.x, 172.16.x, 192.168.x, 127.0.0.1
                  </p>
                  {inputError && (
                    <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', color: '#ff4560', marginTop: '8px' }}>
                      {inputError}
                    </p>
                  )}
                </div>

                <div style={{ marginBottom: '24px' }}>
                  <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', color: 'rgba(240,237,232,0.35)', marginBottom: '10px', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                    Scan Mode
                  </p>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button type="button" style={modeBtn('fast')} onClick={() => setScanMode('fast')}>Fast</button>
                    <button type="button" style={modeBtn('deep')} onClick={() => setScanMode('deep')}>Deep</button>
                    <button type="button" style={modeBtn('pen_test')} onClick={() => setScanMode('pen_test')}>Pen Test</button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={!!inputError || !target.trim() || phase !== 'idle'}
                  style={{
                    width: '100%',
                    fontFamily: "'JetBrains Mono',monospace",
                    fontSize: '11px',
                    fontWeight: 500,
                    letterSpacing: '0.12em',
                    textTransform: 'uppercase',
                    color: '#060608',
                    background: '#00ff88',
                    border: 'none',
                    padding: '14px 36px',
                    cursor: (inputError || !target.trim()) ? 'not-allowed' : 'pointer',
                    opacity: (inputError || !target.trim()) ? 0.5 : 1,
                    clipPath: 'polygon(10px 0%, 100% 0%, calc(100% - 10px) 100%, 0% 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '10px',
                  }}
                >
                  Initialize Scan →
                </button>
              </form>
            </div>
          )}

          {/* Terminal Log */}
          {phase !== 'idle' && (
            <div style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {/* Progress bar */}
              <div style={{
                height: '2px',
                background: 'rgba(255,255,255,0.05)',
                width: '100%',
                position: 'relative',
              }}>
                <div style={{
                  height: '100%',
                  width: `${getProgress()}%`,
                  background: phase === 'failed' ? '#ff4560' : '#00ff88',
                  transition: 'width 0.8s ease',
                }} />
              </div>

              {/* Terminal header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ff5f57' }} />
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ffbd2e' }} />
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#28c840' }} />
                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', color: 'rgba(240,237,232,0.3)', letterSpacing: '0.1em', marginLeft: '4px' }}>
                  netsec-ai — scanner kernel
                </span>
                <div style={{ marginLeft: 'auto' }}>
                  <span style={{
                    fontFamily: "'JetBrains Mono',monospace",
                    fontSize: '9px',
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    padding: '2px 8px',
                    border: `1px solid ${phaseColors[phase] || '#fff'}`,
                    color: phaseColors[phase] || '#fff',
                    background: `${phaseColors[phase] || '#fff'}11`,
                  }}>
                    {phase.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Log body */}
              <div
                ref={logBodyRef}
                className="log-scroll"
                style={{
                  fontFamily: "'JetBrains Mono',monospace",
                  fontSize: '11px',
                  lineHeight: 1.8,
                  padding: '16px 20px',
                  maxHeight: '380px',
                  overflowY: 'auto',
                }}
              >
                {logs.map((log, i) => (
                  <div key={i} style={{ display: 'flex', gap: '10px', marginBottom: '2px' }}>
                    <span style={{ color: 'rgba(240,237,232,0.3)', flexShrink: 0 }}>{log.time}</span>
                    <span style={{
                      color: log.tagType === 'ok' ? '#00ff88'
                        : log.tagType === 'err' ? '#ff4560'
                          : log.tagType === 'warn' ? '#ffb340'
                            : '#4af4ff',
                      flexShrink: 0,
                    }}>
                      [{log.tag}]
                    </span>
                    <span style={{ color: 'rgba(240,237,232,0.7)', wordBreak: 'break-all' }}>
                      {log.message}
                    </span>
                    {i === logs.length - 1 && phase !== 'complete' && phase !== 'failed' && (
                      <span style={{
                        display: 'inline-block',
                        width: '7px',
                        height: '13px',
                        background: '#00ff88',
                        animation: 'blink 1s step-end infinite',
                        verticalAlign: 'middle',
                        marginLeft: '4px',
                      }} />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* New Scan button after complete/failed */}
          {phase === 'complete' && (
            <button
              onClick={handleNewScan}
              style={{
                marginTop: '16px',
                fontFamily: "'JetBrains Mono',monospace",
                fontSize: '10px',
                textTransform: 'uppercase',
                letterSpacing: '0.12em',
                color: 'rgba(240,237,232,0.5)',
                background: 'transparent',
                border: '1px solid rgba(255,255,255,0.08)',
                padding: '10px 20px',
                cursor: 'pointer',
                width: '100%',
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'
                e.currentTarget.style.color = '#f0ede8'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'
                e.currentTarget.style.color = 'rgba(240,237,232,0.5)'
              }}
            >
              ← New Scan
            </button>
          )}
        </div>

        {/* RIGHT — Results Panel */}
        {phase === 'complete' && results && (
          <div className="results-panel" style={{ width: '55%' }}>
            {/* Tabs */}
            <div style={{ display: 'flex', marginBottom: '24px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              {['report', 'cve', 'raw'].map((tab) => (
                <button key={tab} style={tabBtn(tab)} onClick={() => setActiveTab(tab)}>
                  {tab === 'report' ? 'AI Report' : tab === 'cve' ? 'CVE Findings' : 'Raw Data'}
                </button>
              ))}
            </div>

            {/* Tab 1: AI Report */}
            {activeTab === 'report' && (
              <div style={{
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255,255,255,0.06)',
                padding: '28px',
                maxHeight: '600px',
                overflowY: 'auto',
              }}>
                <div className="prose-netsec">
                  <ReactMarkdown>{results.ai_summary || 'No report generated.'}</ReactMarkdown>
                </div>
              </div>
            )}

            {/* Tab 2: CVE Findings */}
            {activeTab === 'cve' && (
              <div>
                {/* Ports Grid */}
                <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: 'rgba(240,237,232,0.35)', marginBottom: '12px' }}>
                  Detected Ports ({ports.length})
                </p>
                {ports.length > 0 ? (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', marginBottom: '28px' }}>
                    {ports.map((port, i) => (
                      <div key={i} className="port-card" style={{
                        border: '1px solid rgba(255,255,255,0.07)',
                        padding: '16px',
                        transition: 'border-color 0.2s',
                      }}>
                        <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '24px', color: '#00ff88', fontWeight: 600, marginBottom: '4px', lineHeight: 1 }}>
                          {port.portid || port.port || port.port_number || '?'}
                        </p>
                        <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '9px', color: 'rgba(240,237,232,0.4)', letterSpacing: '0.08em', marginBottom: '6px', textTransform: 'uppercase' }}>
                          {port.protocol || port.proto || 'tcp'}
                        </p>
                        <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: '#f0ede8', marginBottom: '2px' }}>
                          {port.service || port.service_name || port.name || 'unknown'}
                        </p>
                        {(port.product || port.product_name) && (
                          <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', color: 'rgba(240,237,232,0.4)' }}>
                            {(port.product || port.product_name)} {(port.version || port.version_string || port.ver)}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.3)', marginBottom: '28px' }}>
                    No open ports detected.
                  </p>
                )}

                {/* CVE Table */}
                <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.15em', color: 'rgba(240,237,232,0.35)', marginBottom: '12px' }}>
                  CVE Findings ({cveFindings.length})
                </p>
                {cveFindings.length === 0 ? (
                  <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.3)', padding: '20px 0', textAlign: 'center' }}>
                    No CVEs matched — service versions may be undetected.
                  </p>
                ) : (
                  <div style={{ overflowX: 'auto', marginBottom: '28px' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr>
                          {['CVE ID', 'CVSS', 'Summary'].map((h) => (
                            <th key={h} style={{
                              fontFamily: "'JetBrains Mono',monospace",
                              fontSize: '10px',
                              textTransform: 'uppercase',
                              letterSpacing: '0.12em',
                              color: 'rgba(240,237,232,0.3)',
                              borderBottom: '1px solid rgba(255,255,255,0.07)',
                              padding: '10px 16px',
                              textAlign: 'left',
                              fontWeight: 400,
                            }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {cveFindings.slice(0, 20).map((cve, i) => {
                          const score = parseCvss(cve.cvss)
                          const scoreColor = score >= 9 ? '#ff4560' : score >= 7 ? '#ffb340' : score >= 4 ? '#4af4ff' : '#00ff88'
                          return (
                            <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                              <td style={{ padding: '12px 16px' }}>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: '#00ff88' }}>
                                  {cve.id || cve.cve_id || 'N/A'}
                                </span>
                              </td>
                              <td style={{ padding: '12px 16px' }}>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: scoreColor }}>
                                  {score.toFixed(1)}
                                </span>
                              </td>
                              <td style={{ padding: '12px 16px' }}>
                                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: 'rgba(240,237,232,0.5)' }}>
                                  {(cve.summary || cve.description || '—').substring(0, 80)}
                                  {(cve.summary || cve.description || '').length > 80 ? '...' : ''}
                                </span>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* CVE Charts */}
                {sevData.length > 0 && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2px' }}>
                    <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', padding: '20px' }}>
                      <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.15em', color: '#00ff88', marginBottom: '16px' }}>
                        Severity Breakdown
                      </p>
                      <ResponsiveContainer width="100%" height={180}>
                        <PieChart>
                          <Pie
                            data={sevData}
                            cx="50%"
                            cy="50%"
                            innerRadius={50}
                            outerRadius={75}
                            paddingAngle={3}
                            dataKey="value"
                          >
                            {sevData.map((_, i) => (
                              <Cell key={i} fill={sevColors[i % sevColors.length]} />
                            ))}
                          </Pie>
                          <Tooltip content={<CustomTooltip />} />
                        </PieChart>
                      </ResponsiveContainer>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
                        {sevData.map((d, i) => (
                          <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: sevColors[i % sevColors.length] }} />
                            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '9px', color: 'rgba(240,237,232,0.4)' }}>
                              {d.name} {d.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', padding: '20px' }}>
                      <p style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.15em', color: '#00ff88', marginBottom: '16px' }}>
                        Top CVEs by Score
                      </p>
                      <ResponsiveContainer width="100%" height={180}>
                        <BarChart data={topCves} layout="vertical" margin={{ top: 0, right: 10, left: -10, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                          <XAxis type="number" domain={[0, 10]} tick={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, fill: 'rgba(240,237,232,0.35)' }} axisLine={false} tickLine={false} />
                          <YAxis type="category" dataKey="id" tick={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 9, fill: '#00ff88' }} axisLine={false} tickLine={false} width={80} />
                          <Tooltip content={<CustomTooltip />} />
                          <Bar dataKey="cvss" fill="#00ff88" radius={[0, 2, 2, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Tab 3: Raw Data */}
            {activeTab === 'raw' && (
              <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', padding: '20px', maxHeight: '600px', overflow: 'auto' }}>
                <pre style={{
                  fontFamily: "'JetBrains Mono',monospace",
                  fontSize: '11px',
                  color: 'rgba(240,237,232,0.6)',
                  lineHeight: 1.6,
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}>
                  {JSON.stringify({ ports, cve_findings: cveFindings }, null, 2)}
                </pre>
              </div>
            )}

            {/* Export Buttons */}
            {phase === 'complete' && (
              <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                <button
                  onClick={downloadJSON}
                  style={{
                    flex: 1,
                    fontFamily: "'JetBrains Mono',monospace",
                    fontSize: '10px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.12em',
                    color: 'rgba(240,237,232,0.5)',
                    background: 'transparent',
                    border: '1px solid rgba(255,255,255,0.08)',
                    padding: '10px 20px',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00ff88'; e.currentTarget.style.color = '#00ff88' }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = 'rgba(240,237,232,0.5)' }}
                >
                  Download JSON
                </button>
                <button
                  onClick={downloadReport}
                  style={{
                    flex: 1,
                    fontFamily: "'JetBrains Mono',monospace",
                    fontSize: '10px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.12em',
                    color: 'rgba(240,237,232,0.5)',
                    background: 'transparent',
                    border: '1px solid rgba(255,255,255,0.08)',
                    padding: '10px 20px',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00ff88'; e.currentTarget.style.color = '#00ff88' }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = 'rgba(240,237,232,0.5)' }}
                >
                  Download Report
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
