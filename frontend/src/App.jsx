import React, { useState } from 'react';
import axios from 'axios';
import { AnimatePresence } from 'framer-motion';
import { Terminal, Shield, Activity, Lock, AlertTriangle, Download, FileText, Code, Layers, Server, Eye, Cpu, Globe, Zap } from 'lucide-react';
import ParticleNetwork from './components/ParticleNetwork';
import ReactMarkdown from 'react-markdown';

// API configuration
const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

// --- COMPONENTS ---

const StatusCard = ({ icon: Icon, title, value, color }) => (
  <div className={`bg-black/40 border border-${color}/30 p-3 rounded flex items-center gap-3 hover:bg-${color}/5 transition-colors`}>
    <div className={`p-2 rounded bg-${color}/10 text-${color}`}>
      <Icon size={18} />
    </div>
    <div>
      <p className="text-[10px] text-gray-500 uppercase tracking-wider">{title}</p>
      <p className="text-sm font-bold text-gray-200">{value}</p>
    </div>
  </div>
);

const TabButton = ({ active, onClick, icon: Icon, label }) => (
  <button 
    onClick={onClick}
    className={`flex items-center gap-2 px-4 py-3 text-xs font-bold uppercase tracking-widest transition-all border-b-2 ${
      active 
        ? 'border-cyber-neon text-cyber-neon bg-cyber-neon/5' 
        : 'border-transparent text-gray-600 hover:text-gray-300'
    }`}
  >
    <Icon size={14} />
    {label}
  </button>
);

const PortCard = ({ port }) => (
  <motion.div 
    initial={{ opacity: 0, y: 10 }}
    animate={{ opacity: 1, y: 0 }}
    className="bg-gray-900/40 border border-gray-700/50 p-4 rounded hover:border-cyber-neon/50 transition-all group relative overflow-hidden"
  >
    <div className="absolute top-0 right-0 p-2 opacity-10 group-hover:opacity-100 transition-opacity">
      <Activity size={40} className="text-cyber-neon"/>
    </div>
    <div className="flex justify-between items-start mb-2 relative z-10">
      <span className="text-3xl font-mono font-bold text-white group-hover:text-cyber-neon transition-colors">{port.port}</span>
      <span className="bg-cyber-neon/10 text-cyber-neon text-[10px] px-2 py-1 rounded border border-cyber-neon/20 uppercase font-bold">
        {port.protocol} / {port.service}
      </span>
    </div>
    <div className="relative z-10 space-y-1">
      <p className="text-xs text-gray-400">
        <span className="text-gray-600 uppercase text-[10px]">Product:</span><br/>
        {port.product || "Generic Service"} <span className="text-gray-500">{port.version}</span>
      </p>
    </div>
    {port.vulnerabilities_found && (
      <div className="mt-3 pt-3 border-t border-gray-700/50 relative z-10">
        <p className="text-cyber-alert text-[10px] font-bold flex items-center gap-1 mb-1">
          <AlertTriangle size={10}/> POTENTIAL VULN
        </p>
        <p className="text-[10px] text-gray-400 line-clamp-2 font-mono bg-black/50 p-1 rounded">
          {port.vulnerabilities_found}
        </p>
      </div>
    )}
  </motion.div>
);

export default function App() {
  const [target, setTarget] = useState('');
  const [status, setStatus] = useState('IDLE');
  const [logs, setLogs] = useState([]);
  const [report, setReport] = useState(null);
  const [rawData, setRawData] = useState(null);
  const [activeTab, setActiveTab] = useState('report');
  const [scanMode, setScanMode] = useState('fast');

  const addLog = (msg) => setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);

  const scanModes = [
    { key: 'fast', label: 'Fast Scan', desc: 'Top 100 ports' },
    { key: 'deep', label: 'Deep Scan', desc: 'All ports + versions' },
    { key: 'pen_test', label: 'Pen Testing', desc: 'Aggressive + traffic capture' }
  ];

  const handleScan = async () => {
    if (!target) return;
    setStatus('SCANNING');
    setLogs([]);
    setReport(null);
    setRawData(null);
    addLog(`INITIATING TARGET LOCK: ${target}`);
    addLog(`SCAN MODE: ${scanMode.toUpperCase()}`);
    
    try {
      addLog(">> DEPLOYING NMAP PROBES...");
      const scanRes = await axios.post(`${API_URL}/api/scan`, { target, scan_mode: scanMode });
      setRawData(scanRes.data.data);
      
      if (scanRes.data.scan_profile) {
        const est = scanRes.data.scan_profile.estimated_seconds;
        addLog(`>> ESTIMATED TIME: ${est.total}s (Nmap: ${est.nmap}s, Scapy: ${est.scapy}s, TShark: ${est.tshark}s)`);
      }
      
      addLog(">> PACKET CAPTURE SUCCESSFUL.");
      
      setStatus('ANALYZING');
      addLog(">> TRANSMITTING COMPRESSED DATA TO GEMINI...");
      const aiRes = await axios.post(`${API_URL}/api/analyze`, scanRes.data.data);
      
      setReport(aiRes.data.report);
      setStatus('COMPLETE');
      addLog(">> THREAT ASSESSMENT RECEIVED.");
      
    } catch (error) {
      setStatus('ERROR');
      addLog(`!! CRITICAL FAILURE: ${error?.response?.data?.detail || error.message}`);
    }
  };

  const handleExport = (type) => {
    if (!report && !rawData) return;
    let content, filename, mime;

    if (type === 'json') {
      content = JSON.stringify(rawData, null, 2);
      filename = `scan_${target}.json`;
      mime = 'application/json';
    } else if (type === 'md') {
      content = report;
      filename = `report_${target}.md`;
      mime = 'text/markdown';
    } else if (type === 'pdf') {
      window.print();
      return;
    }

    const blob = new Blob([content], { type: mime });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="relative min-h-screen text-gray-300 font-mono selection:bg-cyber-neon selection:text-black">
      <ParticleNetwork />
      
      <div className="relative z-10 container mx-auto p-4 lg:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 h-screen">
        
        {/* LEFT COLUMN */}
        <div className="lg:col-span-4 flex flex-col gap-6 print:hidden">
          <motion.div 
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            className="bg-cyber-dark/80 backdrop-blur-md border border-cyber-neon/30 p-6 rounded shadow-[0_0_15px_rgba(0,243,255,0.1)]"
          >
            <div className="flex items-center gap-3 mb-6">
              <Shield className="w-8 h-8 text-cyber-neon" />
              <div>
                <h1 className="text-xl font-bold text-white tracking-tighter leading-none">NETSEC_AI</h1>
                <span className="text-[10px] text-cyber-neon/70 uppercase tracking-widest">Auto-Pentester</span>
              </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="text-[10px] text-gray-500 uppercase font-bold tracking-wider">Target Assignment</label>
                <input 
                  type="text" 
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="192.168.1.1"
                  className="w-full mt-2 bg-black/50 border border-cyber-neon/30 rounded p-3 text-cyber-neon focus:outline-none focus:border-cyber-neon focus:ring-1 focus:ring-cyber-neon transition-all"
                />
              </div>

              <div>
                <label className="text-[10px] text-gray-500 uppercase font-bold tracking-wider">Scan Mode</label>
                <div className="mt-2 bg-black/50 border border-cyber-neon/30 rounded p-3 space-y-2">
                  <div className="flex gap-2">
                    {scanModes.map((mode) => (
                      <button
                        key={mode.key}
                        onClick={() => setScanMode(mode.key)}
                        className={`flex-1 py-2 px-2 text-[10px] font-bold uppercase tracking-wider rounded transition-all ${
                          scanMode === mode.key
                            ? 'bg-cyber-neon text-gray-700 border border-cyber-neon shadow-[0_0_10px_rgba(0,243,255,0.4)] hover:shadow-[0_0_15px_rgba(0,243,255,0.6)]'
                            : 'bg-black/50 text-gray-400 border border-gray-700 hover:border-cyber-neon/50'
                        }`}
                      >
                        {mode.label}
                      </button>
                    ))}
                  </div>
                  <p className="text-[9px] text-gray-500 italic">
                    {scanModes.find(m => m.key === scanMode)?.desc}
                  </p>
                </div>
              </div>
              
              <button 
                onClick={handleScan}
                disabled={status === 'SCANNING' || status === 'ANALYZING'}
                className={`w-full py-4 font-bold uppercase tracking-widest transition-all duration-300 flex items-center justify-center gap-2 text-xs rounded border
                  ${status === 'IDLE' || status === 'COMPLETE' || status === 'ERROR' 
                    ? 'bg-cyber-neon/20 text-cyber-neon border-cyber-neon hover:text-white hover:scale-105 hover:shadow-[0_0_25px_rgba(0,243,255,0.6)]' 
                    : 'bg-gray-800 text-gray-500 border-gray-700 cursor-not-allowed'}`}
              >
                {status === 'SCANNING' || status === 'ANALYZING' ? (
                  <> <Activity className="w-4 h-4 animate-spin"/> PROCESSING... </>
                ) : (
                  <> <Lock className="w-4 h-4"/> INITIATE SCAN </>
                )}
              </button>
            </div>
          </motion.div>

          <motion.div className="flex-1 bg-black/90 border border-gray-800 rounded p-4 overflow-hidden flex flex-col font-mono text-xs">
            <div className="flex items-center gap-2 text-gray-500 mb-2 border-b border-gray-800 pb-2">
              <Terminal className="w-3 h-3" />
              <span className="uppercase tracking-wider">Kernel Log</span>
            </div>
            <div className="flex-1 overflow-y-auto space-y-1 scrollbar-thin font-medium">
              {logs.map((log, i) => (
                <div key={i} className="text-green-500/90 break-all border-l-2 border-transparent pl-2 hover:bg-gray-900/50">
                  <span className="opacity-40 mr-2">{'>'}</span>{log}
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* RIGHT COLUMN */}
        <div className="lg:col-span-8 flex flex-col h-full overflow-hidden">
          <AnimatePresence mode="wait">
            {!report && !rawData ? (
              <motion.div 
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="h-full flex flex-col items-center justify-center border border-dashed border-gray-800 rounded bg-black/20"
              >
                <div className="p-6 rounded-full bg-gray-900/50 mb-4">
                  <Server className="w-12 h-12 text-gray-700" />
                </div>
                <p className="text-gray-600 uppercase tracking-widest text-xs">Awaiting Telemetry</p>
              </motion.div>
            ) : (
              <motion.div 
                key="dashboard"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                className="h-full bg-cyber-dark/95 backdrop-blur-xl border border-gray-800 rounded overflow-hidden flex flex-col shadow-2xl"
              >
                {/* METRICS ROW */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 p-4 bg-black/40 border-b border-gray-800">
                  <StatusCard icon={Globe} title="Target" value={rawData?.target} color="cyber-neon" />
                  <StatusCard icon={Layers} title="Ports" value={rawData?.hosts?.[0]?.open_ports?.length || 0} color="blue-500" />
                  <StatusCard icon={Shield} title="Firewall" value={rawData?.firewall_analysis?.firewall_status ? rawData.firewall_analysis.firewall_status : (rawData?.firewall_analysis?.error ? "Auth Error" : "N/A")} color="purple-500" />
                  <StatusCard icon={AlertTriangle} title="Status" value="Scan Complete" color="green-500" />
                </div>

                {/* TABS HEADER & DOWNLOAD BUTTONS */}
                <div className="flex items-center justify-between px-4 border-b border-gray-800 bg-black/20">
                  <div className="flex gap-2">
                    <TabButton active={activeTab === 'report'} onClick={() => setActiveTab('report')} icon={FileText} label="Analyst Report" />
                    <TabButton active={activeTab === 'technical'} onClick={() => setActiveTab('technical')} icon={Cpu} label="Technical Data" />
                    <TabButton active={activeTab === 'json'} onClick={() => setActiveTab('json')} icon={Code} label="Raw Source" />
                  </div>
                  <div className="flex gap-2 print:hidden">
                    <button onClick={() => handleExport('json')} className="p-2 text-gray-500 hover:text-cyber-neon border border-gray-800 rounded hover:border-cyber-neon transition-all" title="Export JSON"><Code size={16}/></button>
                    <button onClick={() => handleExport('md')} className="p-2 text-gray-500 hover:text-cyber-neon border border-gray-800 rounded hover:border-cyber-neon transition-all" title="Export Markdown"><FileText size={16}/></button>
                    <button onClick={() => handleExport('pdf')} className="p-2 text-gray-500 hover:text-cyber-neon border border-gray-800 rounded hover:border-cyber-neon transition-all" title="Print PDF"><Download size={16}/></button>
                  </div>
                </div>

                {/* CONTENT AREA */}
                <div className="flex-1 overflow-y-auto p-6 bg-gradient-to-b from-black/50 to-transparent">
                  
                  {/* TAB 1: EXECUTIVE REPORT */}
                  {activeTab === 'report' && (
                    <div className="space-y-8">
                      {/* AI Report */}
                      <div className="prose prose-invert prose-headings:text-white prose-p:text-gray-400 max-w-none">
                       {/* Custom Renderers to style the Markdown nicely */}
                       <ReactMarkdown
                          components={{
                            h1: (props) => <div className="flex items-center gap-3 text-2xl font-bold text-cyber-neon mb-6 border-b border-cyber-neon/20 pb-2 uppercase tracking-widest"><Shield className="w-6 h-6"/> <span {...props}/></div>,
                            h2: (props) => <div className="mt-8 mb-4 text-lg font-bold text-white flex items-center gap-2 border-l-4 border-cyber-neon pl-3 py-1 bg-cyber-neon/5"><span {...props}/></div>,
                            strong: (props) => <span className="text-cyber-neon font-bold" {...props} />,
                            ul: (props) => <ul className="grid grid-cols-1 gap-2 my-4" {...props} />,
                            li: (props) => <li className="bg-gray-900/50 border border-gray-800 p-3 rounded text-sm text-gray-300 flex gap-2 before:content-['>'] before:text-cyber-neon" {...props} />,
                            blockquote: (props) => <div className="border border-red-500/30 bg-red-900/10 p-4 rounded my-4 text-red-200 text-sm flex gap-3 items-start"><AlertTriangle className="shrink-0 w-5 h-5 text-red-500"/><div {...props}/></div>
                          }}
                       >
                         {report}
                       </ReactMarkdown>
                      </div>

                      {/* Critical Threats Port List */}
                      {rawData?.hosts?.[0]?.open_ports && rawData.hosts[0].open_ports.length > 0 && (
                        <div className="border-t border-gray-800 pt-6 mt-6">
                          <h3 className="text-sm text-gray-500 uppercase font-bold mb-4 flex items-center gap-2"><AlertTriangle size={16} className="text-red-500"/> Detected Open Ports</h3>
                          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                            {rawData.hosts[0].open_ports.map((port, idx) => (
                              <PortCard key={idx} port={port} />
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB 2: TECHNICAL DATA (GRID + EXPERT MODE) */}
                  {activeTab === 'technical' && rawData?.hosts?.[0] && (
                    <div className="space-y-8 animate-in fade-in zoom-in duration-300">
                      
                      {/* Section 1: Port Grid */}
                      <div>
                        <h3 className="text-sm text-gray-500 uppercase font-bold mb-4 flex items-center gap-2"><Zap size={16}/> Active Services</h3>
                        {rawData.hosts[0].open_ports.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                            {rawData.hosts[0].open_ports.map((port, idx) => (
                              <PortCard key={idx} port={port} />
                            ))}
                          </div>
                        ) : (
                          <div className="p-8 border border-green-500/20 bg-green-500/5 rounded text-center">
                            <Shield className="w-12 h-12 text-green-500 mx-auto mb-2"/>
                            <p className="text-green-400 font-bold">ALL PORTS STEALTH / CLOSED</p>
                          </div>
                        )}
                      </div>

                      {/* Section 2: Expert Details (Genuine Technical Data) */}
                      <div>
                        <h3 className="text-sm text-gray-500 uppercase font-bold mb-4 flex items-center gap-2"><Cpu size={16}/> Deep Packet Inspection</h3>
                        <div className="bg-black border border-gray-800 rounded p-4 font-mono text-xs grid grid-cols-1 md:grid-cols-2 gap-y-4 gap-x-8">
                          <div>
                            <span className="text-gray-600 block mb-1">LATENCY (RTT)</span>
                            <span className="text-cyber-neon">{rawData.scan_stats?.elapsed || "0.00"}s</span>
                          </div>
                          <div>
                            <span className="text-gray-600 block mb-1">TOTAL HOSTS SCANNED</span>
                            <span className="text-white">{rawData.scan_stats?.totalhosts || "1"}</span>
                          </div>
                          <div className="col-span-1 md:col-span-2 border-t border-gray-800 pt-3">
                            <span className="text-gray-600 block mb-1">RAW SCANNED PORT LIST</span>
                            <span className="text-green-600 break-all">
                              {rawData.hosts[0].open_ports.map(p => p.port).join(', ') || "None"}
                            </span>
                          </div>
                          <div className="col-span-1 md:col-span-2 border-t border-gray-800 pt-3">
                             <span className="text-gray-600 block mb-1">FIREWALL PROBE RESPONSE</span>
                             {rawData?.firewall_analysis?.error ? (
                               <div className="bg-red-900/20 border border-red-500/50 p-2 rounded text-red-300 text-[10px]">
                                 <p className="font-bold">⚠️ Probe Failed</p>
                                 <p className="text-[9px] mt-1">{rawData.firewall_analysis.error}</p>
                               </div>
                             ) : (
                               <span className={`px-2 py-1 rounded text-[10px] block ${rawData.firewall_analysis?.firewall_status?.includes('Secure') ? 'bg-green-900/20 text-green-400' : 'bg-yellow-900/20 text-yellow-400'}`}>
                                 {rawData.firewall_analysis?.firewall_status || "No data available"}
                               </span>
                             )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB 3: RAW JSON */}
                  {activeTab === 'json' && (
                    <div className="bg-black border border-gray-800 rounded p-4 h-full overflow-auto">
                      <pre className="text-[10px] text-green-500 font-mono">
                        {JSON.stringify(rawData, null, 2)}
                      </pre>
                    </div>
                  )}

                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}