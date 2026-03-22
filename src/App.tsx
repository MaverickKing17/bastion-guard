/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Terminal, 
  Settings, 
  Lock, 
  Eye, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  ChevronRight, 
  Database, 
  Network, 
  FileText, 
  Activity,
  Search,
  Cpu,
  Clock,
  ExternalLink,
  Copy,
  Download
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { performSecurityScan, ScanResult } from './security-check';

// --- Types ---

type AppMode = 'BLOCK' | 'LOG';
type Tab = 'overview' | 'detectors' | 'rules' | 'engine' | 'log' | 'plugin-files';

interface Detector {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  category: 'PII' | 'Financial' | 'Secrets';
}

interface SecurityRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  category: 'Filesystem' | 'Database' | 'Network';
}

// --- Components ---

const Badge = ({ children, variant }: { children: React.ReactNode, variant: 'crit' | 'high' | 'info' }) => {
  const styles = {
    crit: "bg-red-500/12 text-red-400 border-red-500/30",
    high: "bg-amber-500/12 text-amber-400 border-amber-500/30",
    info: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border ${styles[variant]}`}>
      {children}
    </span>
  );
};

const Toggle = ({ enabled, onChange, label }: { enabled: boolean, onChange: (v: boolean) => void, label: string }) => {
  return (
    <div className="flex items-center gap-3">
      <button 
        onClick={() => onChange(!enabled)}
        className="relative w-[30px] h-[17px] cursor-pointer focus:outline-none"
      >
        <div className={`absolute inset-0 rounded-full transition-colors duration-200 ${enabled ? 'bg-cyan-500' : 'bg-[#1f2535]'}`} />
        <div className={`absolute top-[2px] left-[2px] w-[13px] h-[13px] bg-white rounded-full transition-transform duration-200 ${enabled ? 'translate-x-[13px]' : 'translate-x-0'}`} />
      </button>
      <span className={`text-[10px] font-bold tracking-wider min-w-[26px] text-right ${enabled ? 'text-[#3ddc84]' : 'text-[#4a5568]'}`}>
        {enabled ? 'ON' : 'OFF'}
      </span>
    </div>
  );
};

// --- Main App ---

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [mode, setMode] = useState<AppMode>('BLOCK');
  const [detectors, setDetectors] = useState<Detector[]>([
    { id: 'ssn', name: 'Social Security Numbers', description: 'US SSN regex + checksum validation', enabled: true, category: 'PII' },
    { id: 'cc', name: 'Credit / Debit Card Numbers', description: 'Luhn-validated · PCI-DSS §3.4', enabled: true, category: 'PII' },
    { id: 'email', name: 'Email Addresses', description: 'RFC 5321 pattern · GDPR Art.4', enabled: true, category: 'PII' },
    { id: 'phone', name: 'Phone Numbers', description: 'E.164 + NANP formats', enabled: false, category: 'PII' },
    { id: 'swift', name: 'SWIFT / BIC Codes', description: 'ISO 9362 bank routing identifiers', enabled: true, category: 'Financial' },
    { id: 'iban', name: 'IBAN / Account Numbers', description: 'ISO 13616 · modulo-97 checksum', enabled: true, category: 'Financial' },
    { id: 'secrets', name: 'AWS / GCP Secrets', description: 'High-entropy key detection · >3.5 bits/char', enabled: true, category: 'Secrets' },
  ]);
  const [rules, setRules] = useState<SecurityRule[]>([
    { id: 'path', name: 'Privileged path writes', description: 'Block writes to /etc, /sys, /boot', enabled: true, category: 'Filesystem' },
    { id: 'bash', name: 'Destructive Bash patterns', description: 'rm -rf / · dd · shred on prod', enabled: true, category: 'Filesystem' },
    { id: 'db', name: 'Prod DB write guard', description: 'Block INSERT/UPDATE/DELETE on prod schemas', enabled: true, category: 'Database' },
    { id: 'exfil', name: 'Exfiltration heuristics', description: 'curl/wget piping large data to external hosts', enabled: false, category: 'Network' },
  ]);

  const [terminalInput, setTerminalInput] = useState('');
  const [terminalHistory, setTerminalHistory] = useState<{cmd: string, output: string | React.ReactNode}[]>([]);
  const [activeAlert, setActiveAlert] = useState<ScanResult | null>(null);
  const [countdown, setCountdown] = useState(30);
  const [isScanning, setIsScanning] = useState(false);

  // Simulation of terminal
  const handleCommand = (e: React.FormEvent) => {
    e.preventDefault();
    if (!terminalInput.trim()) return;

    const cmd = terminalInput;
    setTerminalInput('');
    setIsScanning(true);

    // Simulate scan latency
    setTimeout(() => {
      const result = performSecurityScan(cmd, mode);
      setIsScanning(false);

      if (result.verdict === 'BLOCK') {
        setActiveAlert(result);
        setCountdown(30);
      } else if (result.verdict === 'WARN') {
        setTerminalHistory(prev => [...prev, { 
          cmd, 
          output: (
            <div className="text-amber-500 bg-amber-500/5 border border-amber-500/20 p-2 rounded mt-1 text-[11px]">
              [WARN] BastionAudit: Potential security risk detected. Logging event.
              {result.threats.map((t, i) => <div key={i} className="ml-2 mt-1 opacity-80">→ {t.type}: {t.match.substring(0, 10)}...</div>)}
            </div>
          )
        }]);
      } else {
        setTerminalHistory(prev => [...prev, { cmd, output: <span className="text-[#3ddc84]">Command executed successfully.</span> }]);
      }
    }, 300);
  };

  useEffect(() => {
    let timer: number;
    if (activeAlert) {
      timer = window.setInterval(() => {
        setCountdown(prev => {
          if (prev <= 1) {
            setActiveAlert(null);
            setTerminalHistory(prevHist => [...prevHist, { 
              cmd: '...', 
              output: <span className="text-red-500">Command auto-aborted (Timeout).</span> 
            }]);
            return 30;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [activeAlert]);

  const handleAlertAction = (action: 'ABORT' | 'MASK' | 'REVIEW') => {
    setActiveAlert(null);
    let output: React.ReactNode;
    switch(action) {
      case 'ABORT': output = <span className="text-red-500">Command aborted by user.</span>; break;
      case 'MASK': output = <span className="text-cyan-500">Command masked and remediated. Executing safe version.</span>; break;
      case 'REVIEW': output = <span className="text-amber-500">Manual review requested. Escalating to security team.</span>; break;
    }
    setTerminalHistory(prev => [...prev, { cmd: '...', output }]);
  };

  return (
    <div className="min-h-screen bg-[#0c0e12] text-[#d8dde8] font-mono selection:bg-cyan-500/30">
      {/* --- Main Layout --- */}
      <div className="max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-[280px_1fr] h-screen overflow-hidden border-x border-[#1f2535]">
        
        {/* --- Sidebar --- */}
        <aside className="bg-[#13161c] border-r border-[#1f2535] flex flex-col">
          <div className="p-6 flex items-center gap-3 border-bottom border-[#1f2535]">
            <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/20 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-cyan-500" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight">BastionAudit</h1>
              <p className="text-[10px] text-[#4a5568] uppercase tracking-widest">Security Engine</p>
            </div>
          </div>

          <nav className="flex-1 py-4 overflow-y-auto">
            <div className="px-6 mb-2 text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold">Configuration</div>
            <NavItem active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} icon={<Activity size={14} />} label="Overview" />
            <NavItem active={activeTab === 'detectors'} onClick={() => setActiveTab('detectors')} icon={<Search size={14} />} label="PII Detectors" />
            <NavItem active={activeTab === 'rules'} onClick={() => setActiveTab('rules')} icon={<Lock size={14} />} label="Security Rules" />
            <NavItem active={activeTab === 'engine'} onClick={() => setActiveTab('engine')} icon={<Cpu size={14} />} label="Engine" />
            
            <div className="mx-6 my-4 border-t border-[#1f2535]" />
            
            <div className="px-6 mb-2 text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold">Session</div>
            <NavItem active={activeTab === 'log'} onClick={() => setActiveTab('log')} icon={<FileText size={14} />} label="Audit Log" />
            <NavItem active={activeTab === 'plugin-files'} onClick={() => setActiveTab('plugin-files')} icon={<Terminal size={14} />} label="Plugin Files" />
          </nav>

          <div className="p-4 bg-[#181c24] border-t border-[#1f2535]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-[#4a5568] uppercase font-bold">Status</span>
              <span className="flex items-center gap-1.5 text-[10px] text-[#3ddc84] font-bold">
                <div className="w-1.5 h-1.5 rounded-full bg-[#3ddc84] animate-pulse" />
                ACTIVE
              </span>
            </div>
            <div className="text-[10px] text-[#4a5568]">v2.4.1-stable</div>
          </div>
        </aside>

        {/* --- Main Content --- */}
        <main className="flex flex-col overflow-hidden bg-[#0c0e12]">
          {/* Header */}
          <header className="h-14 border-b border-[#1f2535] bg-[#13161c] flex items-center justify-between px-8">
            <div className="flex items-center gap-2 text-[11px] text-[#4a5568]">
              <span>/bastion-config</span>
              <ChevronRight size={12} />
              <span className="text-[#d8dde8] capitalize">{activeTab.replace('-', ' ')}</span>
            </div>
            <div className="flex items-center gap-4">
              <button className="text-[#4a5568] hover:text-[#d8dde8] transition-colors">
                <Settings size={16} />
              </button>
            </div>
          </header>

          {/* Content Area */}
          <div className="flex-1 overflow-y-auto p-8">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.15 }}
              >
                {activeTab === 'overview' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-[#1f2535] pb-4">
                      <h2 className="text-lg font-bold">Overview</h2>
                      <span className="text-[10.5px] text-[#4a5568]">NorthShield Financial · Production</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <StatCard label="Scanned today" value="247" color="text-[#3ddc84]" />
                      <StatCard label="Blocked" value="3" color="text-red-400" />
                      <StatCard label="Auto-masked" value="2" color="text-cyan-400" />
                    </div>

                    <section className="space-y-4">
                      <h3 className="text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold">Global Mode</h3>
                      <div className="flex gap-3">
                        <button 
                          onClick={() => setMode('BLOCK')}
                          className={`px-4 py-1.5 rounded border font-bold text-[10.5px] transition-all ${mode === 'BLOCK' ? 'bg-red-500/12 text-red-400 border-red-500/35' : 'border-[#1f2535] text-[#4a5568] hover:bg-[#13161c]'}`}
                        >
                          BLOCK
                        </button>
                        <button 
                          onClick={() => setMode('LOG')}
                          className={`px-4 py-1.5 rounded border font-bold text-[10.5px] transition-all ${mode === 'LOG' ? 'bg-amber-500/12 text-amber-400 border-amber-500/35' : 'border-[#1f2535] text-[#4a5568] hover:bg-[#13161c]'}`}
                        >
                          LOG ONLY
                        </button>
                      </div>
                      <div className={`p-3 rounded border text-[10.5px] transition-colors ${mode === 'BLOCK' ? 'bg-amber-500/6 border-amber-500/20 text-amber-500' : 'bg-cyan-500/5 border-cyan-500/20 text-cyan-500'}`}>
                        {mode === 'BLOCK' 
                          ? 'Mode: BLOCK — commands matching rules are hard-intercepted before execution.' 
                          : 'Mode: LOG ONLY — violations are recorded but commands are not blocked.'}
                      </div>
                    </section>

                    <section className="space-y-4">
                      <h3 className="text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold">Terminal Simulation</h3>
                      <div className="bg-[#13161c] border border-[#1f2535] rounded-lg overflow-hidden">
                        <div className="bg-[#181c24] border-b border-[#1f2535] px-4 py-2 flex items-center justify-between">
                          <div className="flex gap-1.5">
                            <div className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
                            <div className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]" />
                            <div className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
                          </div>
                          <span className="text-[10px] text-[#4a5568] uppercase tracking-widest">zsh — /workspace</span>
                        </div>
                        <div className="p-4 h-[200px] overflow-y-auto font-mono text-[12px] space-y-2">
                          {terminalHistory.map((h, i) => (
                            <div key={i}>
                              <div className="flex gap-2">
                                <span className="text-[#3ddc84] font-bold">❯</span>
                                <span className="text-[#8892a4]">{h.cmd}</span>
                              </div>
                              <div className="mt-1">{h.output}</div>
                            </div>
                          ))}
                          {isScanning && (
                            <div className="flex items-center gap-2 text-[#4a5568] italic">
                              <div className="w-3 h-3 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
                              BastionAudit scanning...
                            </div>
                          )}
                        </div>
                        <form onSubmit={handleCommand} className="border-t border-[#1f2535] bg-[#0c0e12] p-3 flex gap-3">
                          <span className="text-[#3ddc84] font-bold">❯</span>
                          <input 
                            type="text" 
                            value={terminalInput}
                            onChange={(e) => setTerminalInput(e.target.value)}
                            placeholder="Try: write /etc/passwd 'root:...' or export AWS_KEY=AKIA..."
                            className="bg-transparent border-none outline-none flex-1 text-[#d8dde8] placeholder-[#4a5568]"
                          />
                        </form>
                      </div>
                    </section>
                  </div>
                )}

                {activeTab === 'detectors' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-[#1f2535] pb-4">
                      <h2 className="text-lg font-bold">PII Detectors</h2>
                      <span className="text-[10.5px] text-[#4a5568]">Configure data classes for detection</span>
                    </div>

                    <div className="space-y-10">
                      {['PII', 'Financial', 'Secrets'].map(cat => (
                        <section key={cat} className="space-y-4">
                          <h3 className="text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold">{cat === 'PII' ? 'Personally Identifiable Information' : cat === 'Financial' ? 'Financial Identifiers' : 'Security Secrets'}</h3>
                          <div className="divide-y divide-[#1f2535] border-t border-[#1f2535]">
                            {detectors.filter(d => d.category === cat).map(d => (
                              <div key={d.id} className="py-4 flex items-center justify-between gap-8">
                                <div>
                                  <div className="text-sm font-medium">{d.name}</div>
                                  <div className="text-[10.5px] text-[#4a5568] mt-0.5">{d.description}</div>
                                </div>
                                <Toggle 
                                  enabled={d.enabled} 
                                  onChange={(v) => setDetectors(prev => prev.map(item => item.id === d.id ? {...item, enabled: v} : item))}
                                  label={d.name}
                                />
                              </div>
                            ))}
                          </div>
                        </section>
                      ))}
                    </div>
                  </div>
                )}

                {activeTab === 'rules' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-[#1f2535] pb-4">
                      <h2 className="text-lg font-bold">Security Rules</h2>
                      <span className="text-[10.5px] text-[#4a5568]">System-level command restrictions</span>
                    </div>

                    <div className="space-y-10">
                      {['Filesystem', 'Database', 'Network'].map(cat => (
                        <section key={cat} className="space-y-4">
                          <h3 className="text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold">{cat}</h3>
                          <div className="divide-y divide-[#1f2535] border-t border-[#1f2535]">
                            {rules.filter(r => r.category === cat).map(r => (
                              <div key={r.id} className="py-4 flex items-center justify-between gap-8">
                                <div>
                                  <div className="text-sm font-medium">{r.name}</div>
                                  <div className="text-[10.5px] text-[#4a5568] mt-0.5">{r.description}</div>
                                </div>
                                <Toggle 
                                  enabled={r.enabled} 
                                  onChange={(v) => setRules(prev => prev.map(item => item.id === r.id ? {...item, enabled: v} : item))}
                                  label={r.name}
                                />
                              </div>
                            ))}
                          </div>
                        </section>
                      ))}
                    </div>
                  </div>
                )}

                {activeTab === 'log' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-[#1f2535] pb-4">
                      <h2 className="text-lg font-bold">Audit Log</h2>
                      <span className="text-[10.5px] text-[#4a5568]">SECURITY_AUDIT.md · session 2026-03-22</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <StatCard label="Open incidents" value="1" color="text-red-400" />
                      <StatCard label="Resolved" value="7" color="text-[#3ddc84]" />
                      <StatCard label="Log size" value="7.2KB" color="text-cyan-400" />
                    </div>

                    <section className="space-y-4">
                      <h3 className="text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold">Recent Events</h3>
                      <div className="space-y-2">
                        <LogEntry id="INC-001" type="Write intercept" path="/etc/cron.d" time="14:07:33" severity="CRITICAL" status="OPEN" />
                        <LogEntry id="INC-002" type="SSN detected" path="env var" time="11:22:14" severity="HIGH" status="DONE" />
                        <LogEntry id="INC-003" type="rm -rf on prod" path="/var/www" time="10:14:08" severity="CRITICAL" status="DONE" />
                      </div>
                    </section>
                  </div>
                )}

                {activeTab === 'plugin-files' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-[#1f2535] pb-4">
                      <h2 className="text-lg font-bold">Plugin Files</h2>
                      <span className="text-[10.5px] text-[#4a5568]">Generated artifacts for Claude Code</span>
                    </div>

                    <div className="grid grid-cols-1 gap-6">
                      <FileView 
                        name="plugin.json" 
                        path=".claude-plugin/plugin.json" 
                        content={`{
  "name": "safe-code-audit",
  "version": "1.0.0",
  "description": "Pre-flight security scanner powered by Bastion Audit",
  "hooks": {
    "PreToolUse": {
      "commands": ["Edit", "Write", "Bash"],
      "handler": "hooks/security-check.js"
    }
  }
}`}
                      />
                      <FileView 
                        name="security-check.js" 
                        path="hooks/security-check.js" 
                        content={`/**
 * BastionAudit: High-performance security scanner.
 * Optimized for low-latency execution (<5ms).
 */
const patterns = {
  API_KEYS: /(?:AKIA|ASIA)[0-9A-Z]{16}|sk-[a-zA-Z0-9]{48}|gh[pousr]_[a-zA-Z0-9]{36,255}/g,
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g,
  CANADIAN_SIN: /\\b\\d{3}-\\d{3}-\\d{3}\\b/g,
  SQL_INJECTION: /\\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\\b.*\\b(FROM|INTO|TABLE|WHERE)\\b/gi
};

const content = process.argv[2] || "";
let threatFound = false;

for (const p in patterns) {
  if (patterns[p].test(content)) {
    threatFound = true;
    break;
  }
}

process.exit(threatFound ? 2 : 0);`}
                      />
                      <FileView 
                        name="SKILL.md" 
                        path="skills/audit/SKILL.md" 
                        content={`# BastionAudit Security Playbook

You are equipped with the BastionAudit security engine.

## Instructions
1. **PII Check**: Before modifying any file, perform a mental check for PII (emails, SINs, keys).
2. **Masking**: Automatically suggest masking for any sensitive output detected during execution.
3. **Audit Logging**: Upon finishing a task, generate or update \`SECURITY_AUDIT.md\` with a summary of security checks performed.

## Severity Meter
- [][][][][] (Low)
- [X][X][X][][] (Medium)
- [X][X][X][X][X] (Critical)`}
                      />
                    </div>
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>

      {/* --- Alert Terminal Overlay --- */}
      <AnimatePresence>
        {activeAlert && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
          >
            <motion.div 
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              className="w-full max-w-[700px] bg-[#0c0e12] border border-[#1f2535] rounded-lg overflow-hidden shadow-2xl"
            >
              <div className="bg-[#181c24] border-b border-[#1f2535] p-3 px-4 flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
                </div>
                <span className="text-[10px] text-[#4a5568] uppercase tracking-widest mx-auto">safe-code-audit — zsh — /workspace</span>
              </div>

              <div className="p-6 border-l-[3px] border-red-500 bg-red-500/5">
                <div className="flex items-center gap-3 mb-4">
                  <div className="bg-red-500/15 border border-red-500/40 text-red-500 text-[10px] font-bold tracking-widest px-2 py-0.5 rounded animate-[pulse-border_2s_ease-in-out_infinite]">
                    INTERCEPT
                  </div>
                  <h3 className="text-red-500 font-bold text-sm tracking-wide uppercase">Bastion Audit Alert</h3>
                  <span className="ml-auto text-[10px] text-[#4a5568]">2026-03-22 · 14:07:33 UTC</span>
                </div>

                <div className="space-y-1 text-[11.5px]">
                  <div className="flex"><span className="w-32 text-[#4a5568]">Session ID</span><span className="text-[#8892a4]">BA-20260322-9F3A</span></div>
                  <div className="flex"><span className="w-32 text-[#4a5568]">Tool type</span><span className="text-red-400">Write / Bash</span></div>
                  <div className="flex"><span className="w-32 text-[#4a5568]">Target path</span><span className="text-amber-400">/etc/cron.d/backup</span></div>
                  <div className="flex"><span className="w-32 text-[#4a5568]">Environment</span><span className="text-[#8892a4]">prod-gke-cluster-us-east-1</span></div>
                </div>

                <div className="mt-6">
                  <div className="text-amber-500 font-bold text-[11.5px] uppercase tracking-wider mb-2">▸ Threat Analysis</div>
                  <div className="bg-amber-500/10 border-l-2 border-amber-500 p-3 rounded-r">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant="crit">Critical</Badge>
                      <span className="text-red-400 font-bold text-[12px]">Privileged write to system crontab</span>
                    </div>
                    <div className="space-y-1 text-[11px]">
                      <div className="flex"><span className="w-32 text-[#4a5568]">Matched rule</span><span className="text-amber-400">RULE-SYS-0091 · CIS Linux 5.1.3</span></div>
                      <div className="flex"><span className="w-32 text-[#4a5568]">Pattern</span><span className="text-amber-400">write → /etc/cron* · root escalation</span></div>
                      <div className="flex"><span className="w-32 text-[#4a5568]">Risk vector</span><span className="text-red-400">Persistence · privilege escalation</span></div>
                    </div>
                  </div>
                </div>

                <div className="mt-6">
                  <div className="text-amber-500 font-bold text-[11.5px] uppercase tracking-wider mb-2">▸ Severity</div>
                  <div className="flex gap-1 mb-2">
                    {[1,2,3,4,5].map(i => <div key={i} className="h-2 flex-1 bg-red-500 rounded-sm" />)}
                    {[6,7,8,9,10].map(i => <div key={i} className="h-2 flex-1 bg-[#1f2535] rounded-sm" />)}
                  </div>
                  <div className="text-[10.5px] text-[#4a5568]">CRITICAL 5/10 · Regulatory exposure: SOC2 CC6.2 · estimated $80K–$2M impact</div>
                </div>

                <div className="mt-6">
                  <div className="text-amber-500 font-bold text-[11.5px] uppercase tracking-wider mb-2">▸ Action Required</div>
                  <div className="bg-cyan-500/5 border-l-2 border-cyan-500 p-3 rounded-r space-y-1.5">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="info">Remediation available</Badge>
                    </div>
                    <RemediationStep n={1} text={<>Use <span className="text-cyan-400">systemd timers</span> instead of crontab for auditable scheduling</>} />
                    <RemediationStep n={2} text={<>Write backup output to <span className="text-cyan-400">/secure/backups/</span> with strict 0600 permissions</>} />
                    <RemediationStep n={3} text={<>Run backup process under dedicated <span className="text-cyan-400">backup-svc</span> user, not root</>} />
                  </div>
                </div>

                <div className="mt-8 pt-4 border-t border-[#1f2535]">
                  <div className="text-red-400 font-bold mb-4">Command blocked. Select an action:</div>
                  <div className="flex flex-wrap gap-3">
                    <button onClick={() => handleAlertAction('ABORT')} className="px-5 py-1.5 rounded border border-red-500/30 bg-red-500/10 text-red-400 font-bold text-[10.5px] tracking-widest hover:bg-red-500/20 transition-all uppercase">Abort Command</button>
                    <button onClick={() => handleAlertAction('MASK')} className="px-5 py-1.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-400 font-bold text-[10.5px] tracking-widest hover:bg-amber-500/20 transition-all uppercase">Mask & Remediate</button>
                    <button onClick={() => handleAlertAction('REVIEW')} className="px-5 py-1.5 rounded border border-[#3ddc84]/30 bg-[#3ddc84]/10 text-[#3ddc84] font-bold text-[10.5px] tracking-widest hover:bg-[#3ddc84]/20 transition-all uppercase">Review Manually</button>
                  </div>
                  <div className="mt-4 text-[10.5px] text-[#4a5568]">
                    Auto-abort in <span className="text-red-500 font-bold">{countdown}</span>s · Audit log: SECURITY_AUDIT.md · Ref: BA-20260322-9F3A
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <style>{`
        @keyframes pulse-border {
          0%, 100% { border-color: rgba(255, 68, 68, 0.3); }
          50% { border-color: rgba(255, 68, 68, 0.9); }
        }
      `}</style>
    </div>
  );
}

// --- Sub-components ---

function NavItem({ active, onClick, icon, label }: { active: boolean, onClick: () => void, icon: React.ReactNode, label: string }) {
  return (
    <button 
      onClick={onClick}
      className={`w-full flex items-center gap-3 px-6 py-2.5 text-[11.5px] transition-all border-l-2 ${active ? 'text-[#d8dde8] bg-cyan-500/5 border-cyan-500' : 'text-[#8892a4] border-transparent hover:text-[#d8dde8] hover:bg-white/5'}`}
    >
      <div className={`${active ? 'text-cyan-500' : 'text-[#4a5568]'}`}>{icon}</div>
      {label}
    </button>
  );
}

function StatCard({ label, value, color }: { label: string, value: string, color: string }) {
  return (
    <div className="bg-[#13161c] border border-[#1f2535] rounded-lg p-4">
      <div className="text-[9.5px] uppercase tracking-widest text-[#4a5568] font-bold mb-1">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}

function LogEntry({ id, type, path, time, severity, status }: any) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[#1f2535] group hover:bg-white/2 cursor-pointer transition-colors">
      <div>
        <div className={`text-[12px] font-bold ${severity === 'CRITICAL' ? 'text-red-400' : 'text-amber-400'}`}>
          {id} · {type} · {path}
        </div>
        <div className="text-[10.5px] text-[#4a5568] mt-0.5">
          {time} · {severity} · {status === 'OPEN' ? 'Pending review' : 'Resolved'}
        </div>
      </div>
      <span className={`text-[10px] font-bold tracking-widest ${status === 'OPEN' ? 'text-red-400' : 'text-[#3ddc84]'}`}>
        {status}
      </span>
    </div>
  );
}

function RemediationStep({ n, text }: { n: number, text: React.ReactNode }) {
  return (
    <div className="flex gap-2 text-[11px] text-[#8892a4]">
      <span className="text-[#4a5568]">{n}.</span>
      <span>{text}</span>
    </div>
  );
}

function FileView({ name, path, content }: { name: string, path: string, content: string }) {
  const [copied, setCopied] = useState(false);
  
  const copy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#13161c] border border-[#1f2535] rounded-lg overflow-hidden">
      <div className="bg-[#181c24] border-b border-[#1f2535] px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText size={14} className="text-[#4a5568]" />
          <span className="text-[11px] font-bold">{name}</span>
          <span className="text-[10px] text-[#4a5568] font-normal">{path}</span>
        </div>
        <div className="flex gap-2">
          <button onClick={copy} className="p-1 text-[#4a5568] hover:text-[#d8dde8] transition-colors relative">
            {copied ? <CheckCircle2 size={14} className="text-[#3ddc84]" /> : <Copy size={14} />}
          </button>
        </div>
      </div>
      <pre className="p-4 text-[11px] text-[#8892a4] overflow-x-auto bg-[#0c0e12]">
        <code>{content}</code>
      </pre>
    </div>
  );
}
