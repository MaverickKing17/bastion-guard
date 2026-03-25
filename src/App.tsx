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
  Download,
  Award,
  MessageSquare,
  Send,
  Globe,
  FileCheck
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { performSecurityScan, ScanResult } from './security-check';
import { GoogleGenAI } from "@google/genai";

// --- Types ---

type AppMode = 'BLOCK' | 'LOG';
type Tab = 'overview' | 'detectors' | 'rules' | 'engine' | 'log' | 'compliance' | 'plugin-files';
type ScanIntensity = 'HIGH_PRECISION' | 'MAX_SPEED';

interface Detector {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  category: 'Personal Identifiable Information' | 'Financial Identifiers' | 'Security Secrets' | 'Canadian Compliance';
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
    crit: "bg-red-950/30 text-red-400 border-red-900/30",
    high: "bg-orange-950/30 text-orange-400 border-orange-900/30",
    info: "bg-blue-950/30 text-blue-400 border-blue-900/30"
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-[10px] font-bold tracking-wider uppercase border shadow-sm ${styles[variant]}`}>
      <div className={`w-1 h-1 rounded-full mr-1.5 ${variant === 'crit' ? 'bg-red-500' : variant === 'high' ? 'bg-orange-500' : 'bg-blue-500'}`} />
      {children}
    </span>
  );
};

const Toggle = ({ enabled, onChange, label }: { enabled: boolean, onChange: (v: boolean) => void, label: string }) => {
  return (
    <div className="flex items-center gap-3">
      <button 
        onClick={() => onChange(!enabled)}
        className="relative w-[40px] h-[22px] cursor-pointer focus:outline-none group"
      >
        <div className={`absolute inset-0 rounded-full transition-all duration-300 ${enabled ? 'bg-[#d97757] shadow-inner' : 'bg-white/5'}`} />
        <div className={`absolute top-[3px] left-[3px] w-[16px] h-[16px] bg-[#f5f5f5] rounded-full shadow-md transition-all duration-300 transform ${enabled ? 'translate-x-[18px]' : 'translate-x-0'} group-hover:scale-110`} />
      </button>
      <span className={`text-[10px] font-bold tracking-widest min-w-[26px] text-right transition-colors duration-300 ${enabled ? 'text-[#d97757]' : 'text-[#a3a3a3]'}`}>
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
    { id: 'sin', name: 'Social Insurance Numbers', description: 'Canadian SIN validation · Luhn-9 checksum', enabled: true, category: 'Personal Identifiable Information' },
    { id: 'cc', name: 'Credit / Debit Card Numbers', description: 'Luhn-validated · PCI-DSS §3.4', enabled: true, category: 'Personal Identifiable Information' },
    { id: 'email', name: 'Email Addresses', description: 'RFC 5321 pattern · GDPR Art.4', enabled: true, category: 'Personal Identifiable Information' },
    { id: 'phone', name: 'Phone Numbers', description: 'E.164 + NANP formats', enabled: false, category: 'Personal Identifiable Information' },
    { id: 'swift', name: 'SWIFT / BIC Codes', description: 'ISO 9362 bank routing identifiers', enabled: true, category: 'Financial Identifiers' },
    { id: 'iban', name: 'IBAN / Account Numbers', description: 'ISO 13616 · modulo-97 checksum', enabled: true, category: 'Financial Identifiers' },
    { id: 'secrets', name: 'AWS / GCP Secrets', description: 'High-entropy key detection · >3.5 bits/char', enabled: true, category: 'Security Secrets' },
    { id: 'osfi-b13', name: 'OSFI B-13 Tech Risk', description: 'Technology and Cyber Risk Management guard', enabled: true, category: 'Canadian Compliance' },
    { id: 'pipeda', name: 'PIPEDA Data Guard', description: 'Personal Information Protection compliance', enabled: true, category: 'Canadian Compliance' },
    { id: 'fintrac', name: 'FINTRAC AML Heuristics', description: 'Anti-Money Laundering transaction monitoring', enabled: true, category: 'Canadian Compliance' },
    { id: 'residency', name: 'Data Residency Guard', description: 'Ensure data stays within Canadian jurisdictions', enabled: true, category: 'Canadian Compliance' },
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
  const [scanIntensity, setScanIntensity] = useState<ScanIntensity>('HIGH_PRECISION');
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<{role: 'user' | 'assistant', content: string}[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [useGemini, setUseGemini] = useState(false);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || isChatLoading) return;

    const userMsg = chatInput;
    setChatInput('');
    setChatMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setIsChatLoading(true);

    if (useGemini) {
      try {
        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });
        const response = await ai.models.generateContent({
          model: "gemini-3.1-pro-preview",
          contents: userMsg,
          config: {
            systemInstruction: "You are BastionAudit AI, a security assistant specialized in Canadian financial compliance (OSFI B-10, B-13, PIPEDA, FINTRAC). You help security admins analyze audit logs, identify PII leaks, and ensure data residency compliance in Canadian banking environments.",
          }
        });
        setChatMessages(prev => [...prev, { role: 'assistant', content: response.text || "I'm sorry, I couldn't generate a response." }]);
      } catch (error) {
        console.error("Gemini Error:", error);
        setChatMessages(prev => [...prev, { role: 'assistant', content: "I encountered an error with the Gemini engine. Please try again later." }]);
      } finally {
        setIsChatLoading(false);
      }
      return;
    }

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          messages: [...chatMessages, { role: 'user', content: userMsg }] 
        }),
      });
      
      const data = await response.json();
      
      if (response.status === 402 || data.code === 'BILLING_ERROR') {
        setChatMessages(prev => [...prev, { 
          role: 'assistant', 
          content: "⚠️ Anthropic Billing Error: Your Claude API credit balance is too low. I recommend switching to the Gemini engine (free) using the toggle above to continue your security audit." 
        }]);
        return;
      }

      if (data.content && data.content[0]) {
        setChatMessages(prev => [...prev, { role: 'assistant', content: data.content[0].text }]);
      } else {
        throw new Error(data.error || "Unknown error");
      }
    } catch (error: any) {
      console.error("Chat Error:", error);
      setChatMessages(prev => [...prev, { role: 'assistant', content: "I'm sorry, I encountered an error connecting to the Claude engine. You can try switching to the Gemini engine using the toggle above." }]);
    } finally {
      setIsChatLoading(false);
    }
  };

  useEffect(() => {
    // Initial terminal output
    setTerminalHistory([
      { 
        cmd: 'bastion --init', 
        output: (
          <div className="space-y-2 text-white/60">
            <div className="flex items-center gap-3">
              <div className="w-1.5 h-1.5 rounded-full bg-[#3ddc84] animate-pulse" />
              <span>Bastion Core v2.4.1 initialized successfully.</span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-1.5 h-1.5 rounded-full bg-[#3ddc84]" />
              <span>Scanning workspace for PII and security vulnerabilities...</span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-1.5 h-1.5 rounded-full bg-[#3ddc84]" />
              <span>Security rules loaded: 4 active, 1 standby.</span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-1.5 h-1.5 rounded-full bg-[#3ddc84]" />
              <span>Claude Code integration: <span className="text-[#3ddc84] font-bold">CONNECTED (MAX 20X)</span></span>
            </div>
            <div className="mt-4 text-[#d97757] font-bold tracking-widest text-[10px] uppercase">
              Ready for command interception.
            </div>
          </div>
        )
      }
    ]);
  }, []);

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
              <div className="mt-1 font-mono text-white/60">Masked: {result.maskedContent}</div>
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
    const masked = activeAlert?.maskedContent;
    setActiveAlert(null);
    let output: React.ReactNode;
    switch(action) {
      case 'ABORT': output = <span className="text-red-500">Command aborted by user.</span>; break;
      case 'MASK': output = (
        <div className="space-y-1">
          <span className="text-cyan-500">Command masked and remediated. Executing safe version.</span>
          <div className="text-[11px] text-white/40 font-mono italic">❯ {masked}</div>
        </div>
      ); break;
      case 'REVIEW': output = <span className="text-amber-500">Manual review requested. Escalating to security team.</span>; break;
    }
    setTerminalHistory(prev => [...prev, { cmd: '...', output }]);
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-[#f5f5f5] font-sans selection:bg-[#d97757]/30">
      {/* --- Main Layout --- */}
      <div className="max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-[280px_1fr] h-screen overflow-hidden border-x border-white/5">
        
        {/* --- Sidebar --- */}
        <aside className="bg-[#111111] border-r border-white/5 flex flex-col shadow-[1px_0_10px_rgba(0,0,0,0.2)]">
          <div className="p-8 flex items-center gap-4 border-b border-white/5">
            <div className="w-12 h-12 bg-[#1a1a1a] border border-white/5 rounded-2xl flex items-center justify-center shadow-sm">
              <Shield className="w-7 h-7 text-[#d97757]" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight font-serif text-[#f5f5f5]">BastionAudit</h1>
              <p className="text-[10px] text-[#a3a3a3] uppercase tracking-[0.2em] font-sans font-bold opacity-70">Security Engine</p>
            </div>
          </div>

          <nav className="flex-1 py-8 overflow-y-auto">
            <div className="px-8 mb-4 text-[10px] uppercase tracking-[0.15em] text-[#a3a3a3] font-bold opacity-60">Configuration</div>
            <NavItem active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} icon={<Activity size={16} />} label="Overview" />
            <NavItem active={activeTab === 'detectors'} onClick={() => setActiveTab('detectors')} icon={<Search size={16} />} label="PII Detectors" />
            <NavItem active={activeTab === 'rules'} onClick={() => setActiveTab('rules')} icon={<Lock size={16} />} label="Security Rules" />
            <NavItem active={activeTab === 'compliance'} onClick={() => setActiveTab('compliance')} icon={<FileCheck size={16} />} label="Compliance" />
            <NavItem active={activeTab === 'engine'} onClick={() => setActiveTab('engine')} icon={<Cpu size={16} />} label="Engine" />
            
            <div className="mx-8 my-6 border-t border-white/5" />
            
            <div className="px-8 mb-4 text-[10px] uppercase tracking-[0.15em] text-[#a3a3a3] font-bold opacity-60">Session</div>
            <NavItem active={activeTab === 'log'} onClick={() => setActiveTab('log')} icon={<FileText size={16} />} label="Audit Log" />
            <NavItem active={activeTab === 'plugin-files'} onClick={() => setActiveTab('plugin-files')} icon={<Terminal size={16} />} label="Plugin Files" />
          </nav>

          <div className="p-6 bg-[#1a1a1a]/30 border-t border-white/5">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] text-[#a3a3a3] uppercase font-bold tracking-wider">System Status</span>
              <span className="flex items-center gap-2 text-[10px] text-[#3ddc84] font-bold">
                <div className="w-2 h-2 rounded-full bg-[#3ddc84] shadow-[0_0_8px_rgba(61,220,132,0.5)] animate-pulse" />
                ACTIVE
              </span>
            </div>
            <div className="text-[10px] text-[#a3a3a3] font-medium opacity-60">Build v2.4.1-stable · Enterprise</div>
          </div>
        </aside>

        {/* --- Main Content --- */}
        <main className="flex flex-col overflow-hidden bg-[#0a0a0a]">
          {/* Header */}
          <header className="h-20 border-b border-white/5 bg-[#111111]/80 backdrop-blur-md flex items-center justify-between px-10 sticky top-0 z-10">
            <div className="flex items-center gap-3 text-[12px] text-[#a3a3a3]">
              <span className="hover:text-[#f5f5f5] cursor-pointer transition-colors">/bastion-config</span>
              <ChevronRight size={14} className="opacity-40" />
              <span className="text-[#f5f5f5] font-bold capitalize tracking-tight">{activeTab.replace('-', ' ')}</span>
            </div>
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-3 pr-6 border-r border-white/5">
                <div className="text-right">
                  <div className="text-[11px] font-bold text-[#f5f5f5]">King Narmer</div>
                  <div className="text-[9px] text-[#a3a3a3] uppercase tracking-wider font-bold opacity-60">Security Admin</div>
                </div>
                <div className="w-9 h-9 rounded-full bg-gradient-to-br from-[#d97757] to-[#b45309] flex items-center justify-center text-white font-bold text-xs shadow-md">
                  KN
                </div>
              </div>
              <button className="text-[#a3a3a3] hover:text-[#f5f5f5] transition-all transform hover:rotate-90 duration-300">
                <Settings size={18} />
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
                    <div className="flex items-baseline justify-between border-b border-white/5 pb-4">
                      <h2 className="text-2xl font-serif font-medium">Overview</h2>
                      <span className="text-[10.5px] text-[#a3a3a3] uppercase tracking-widest font-bold">NorthShield Financial · Production</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <StatCard label="Scanned today" value="247" color="text-[#3ddc84]" />
                      <StatCard label="Blocked" value="3" color="text-red-500" />
                      <StatCard label="Auto-masked" value="2" color="text-[#d97757]" />
                    </div>

                    <section className="space-y-6">
                      <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">Claude Code Program Status</h3>
                      <div className="bg-[#141414] border border-white/5 rounded-2xl p-8 shadow-sm space-y-6">
                        <div className="flex items-start gap-6">
                          <div className="w-12 h-12 rounded-2xl bg-[#d97757]/10 flex items-center justify-center text-[#d97757] shrink-0">
                            <Award size={24} />
                          </div>
                          <div className="space-y-2">
                            <div className="text-[16px] font-bold text-[#f5f5f5]">Claude for Open Source Program</div>
                            <p className="text-[13px] text-[#a3a3a3] leading-relaxed">
                              BastionAudit is optimized for the <span className="text-[#f5f5f5] font-bold">Claude Max 20x</span> plan, providing 20x usage capacity and full access to the Claude Code terminal tool.
                            </p>
                          </div>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-white/5">
                          <div className="flex items-center gap-3 text-[12px] text-[#a3a3a3]">
                            <CheckCircle2 size={16} className="text-[#3ddc84]" />
                            <span>5,000+ GitHub Stars Requirement Met</span>
                          </div>
                          <div className="flex items-center gap-3 text-[12px] text-[#a3a3a3]">
                            <CheckCircle2 size={16} className="text-[#3ddc84]" />
                            <span>1M+ Monthly NPM Downloads Met</span>
                          </div>
                        </div>
                      </div>
                    </section>

                    <section className="space-y-6">
                      <div className="flex items-center justify-between">
                        <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">Global Enforcement Mode</h3>
                        <div className="flex items-center gap-2 px-3 py-1 bg-white/[0.03] rounded-md border border-white/5 text-[9px] text-[#a3a3a3] font-bold uppercase tracking-widest">
                          <Shield size={10} />
                          Active Protection
                        </div>
                      </div>
                      <div className="flex gap-4">
                        <button 
                          onClick={() => setMode('BLOCK')}
                          className={`flex-1 px-8 py-4 rounded-2xl border-2 font-bold text-[13px] tracking-tight transition-all duration-300 flex items-center justify-center gap-3 shadow-sm ${mode === 'BLOCK' ? 'bg-red-600 text-white border-red-600 shadow-lg shadow-red-600/20' : 'bg-[#141414] border-white/5 text-[#a3a3a3] hover:border-red-900/50 hover:text-red-500'}`}
                        >
                          <XCircle size={18} />
                          STRICT BLOCK
                        </button>
                        <button 
                          onClick={() => setMode('LOG')}
                          className={`flex-1 px-8 py-4 rounded-2xl border-2 font-bold text-[13px] tracking-tight transition-all duration-300 flex items-center justify-center gap-3 shadow-sm ${mode === 'LOG' ? 'bg-[#d97757] text-white border-[#d97757] shadow-lg shadow-[#d97757]/20' : 'bg-[#141414] border-white/5 text-[#a3a3a3] hover:border-orange-900/50 hover:text-[#d97757]'}`}
                        >
                          <Activity size={18} />
                          LOG & MONITOR
                        </button>
                      </div>
                      <div className={`p-6 rounded-2xl border-2 text-[13px] leading-relaxed transition-all duration-500 flex items-start gap-4 ${mode === 'BLOCK' ? 'bg-red-950/20 border-red-900/30 text-red-200' : 'bg-orange-950/20 border-orange-900/30 text-orange-200'}`}>
                        <div className={`mt-0.5 p-1.5 rounded-lg ${mode === 'BLOCK' ? 'bg-red-900/40' : 'bg-orange-900/40'}`}>
                          <AlertTriangle size={16} />
                        </div>
                        <div>
                          <span className="font-bold block mb-1">{mode === 'BLOCK' ? 'Strict Enforcement Active' : 'Monitoring Mode Active'}</span>
                          {mode === 'BLOCK' 
                            ? 'BastionAudit is in hard-intercept mode. Any command matching security rules or containing high-severity PII will be blocked before execution.' 
                            : 'BastionAudit is in passive mode. Violations are recorded in the audit log and security team is notified, but commands are allowed to proceed.'}
                        </div>
                      </div>
                    </section>

                    <section className="space-y-6">
                      <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#6b6b6b] font-bold opacity-60">Terminal Simulation</h3>
                      <div className="bg-[#0a0a0a] border border-black/20 rounded-2xl overflow-hidden shadow-2xl ring-1 ring-white/5">
                        <div className="bg-[#1a1a1a] border-b border-white/5 px-6 py-3 flex items-center justify-between">
                          <div className="flex gap-2">
                            <div className="w-3 h-3 rounded-full bg-[#ff5f57] shadow-inner" />
                            <div className="w-3 h-3 rounded-full bg-[#ffbd2e] shadow-inner" />
                            <div className="w-3 h-3 rounded-full bg-[#28c840] shadow-inner" />
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-md border border-white/5">
                              <Network size={10} className="text-white/40" />
                              <span className="text-[9px] text-white/40 uppercase tracking-widest font-bold">Bastion-v2</span>
                            </div>
                            <span className="text-[10px] text-white/40 uppercase tracking-[0.2em] font-bold">zsh — /workspace</span>
                          </div>
                        </div>
                        <div className="p-8 h-[300px] overflow-y-auto font-mono text-[13px] space-y-4 scrollbar-thin scrollbar-thumb-white/10">
                          {terminalHistory.map((h, i) => (
                            <div key={i} className="animate-in fade-in slide-in-from-left-2 duration-300">
                              <div className="flex gap-4">
                                <span className="text-[#3ddc84] font-bold opacity-80">❯</span>
                                <span className="text-white/90 leading-relaxed">{h.cmd}</span>
                              </div>
                              <div className="mt-3 pl-7">{h.output}</div>
                            </div>
                          ))}
                          {isScanning && (
                            <div className="flex items-center gap-4 text-white/30 italic pl-7">
                              <div className="w-5 h-5 border-2 border-white/5 border-t-[#d97757] rounded-full animate-spin" />
                              <span className="text-[11px] tracking-wider">BastionAudit deep scanning...</span>
                            </div>
                          )}
                        </div>
                        <form onSubmit={handleCommand} className="border-t border-white/5 bg-[#0a0a0a] p-6 flex gap-4 items-center">
                          <span className="text-[#3ddc84] font-bold text-lg">❯</span>
                          <input 
                            type="text" 
                            value={terminalInput}
                            onChange={(e) => setTerminalInput(e.target.value)}
                            placeholder="Try: write /etc/passwd 'root:...' or export AWS_KEY=AKIA..."
                            className="bg-transparent border-none outline-none flex-1 text-white/90 placeholder-white/10 text-[14px] font-mono"
                          />
                          <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-lg border border-white/5 text-[9px] text-white/30 font-bold uppercase tracking-widest">
                            <Clock size={10} />
                            Real-time
                          </div>
                        </form>
                      </div>
                    </section>
                  </div>
                )}

                {activeTab === 'detectors' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-white/5 pb-4">
                      <h2 className="text-2xl font-serif font-medium">PII Detectors</h2>
                      <span className="text-[10.5px] text-[#a3a3a3] uppercase tracking-widest font-bold">Configure data classes for detection</span>
                    </div>

                    <div className="space-y-16">
                      {['Personal Identifiable Information', 'Financial Identifiers', 'Security Secrets'].map(cat => (
                        <section key={cat} className="space-y-8">
                          <div className="flex items-center gap-4">
                            <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">{cat}</h3>
                            <div className="h-px flex-1 bg-white/5" />
                          </div>
                          <div className="grid grid-cols-1 gap-4">
                            {detectors.filter(d => d.category === cat).map(d => (
                              <div key={d.id} className="p-6 bg-[#141414] border border-white/5 rounded-2xl flex items-center justify-between gap-8 hover:shadow-md transition-all duration-300 group">
                                <div className="flex items-center gap-5">
                                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center transition-colors ${d.enabled ? 'bg-[#d97757]/10 text-[#d97757]' : 'bg-white/5 text-[#a3a3a3]'}`}>
                                    {cat === 'Personal Identifiable Information' ? <Eye size={20} /> : cat === 'Financial Identifiers' ? <Database size={20} /> : <Lock size={20} />}
                                  </div>
                                  <div>
                                    <div className="text-[15px] font-bold text-[#f5f5f5] tracking-tight">{d.name}</div>
                                    <div className="text-[12px] text-[#a3a3a3] mt-1 font-medium opacity-70">{d.description}</div>
                                  </div>
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
                    <div className="flex items-baseline justify-between border-b border-white/5 pb-4">
                      <h2 className="text-2xl font-serif font-medium">Security Rules</h2>
                      <span className="text-[10.5px] text-[#a3a3a3] uppercase tracking-widest font-bold">System-level command restrictions</span>
                    </div>

                    <div className="space-y-16">
                      {['Filesystem', 'Database', 'Network'].map(cat => (
                        <section key={cat} className="space-y-8">
                          <div className="flex items-center gap-4">
                            <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">{cat}</h3>
                            <div className="h-px flex-1 bg-white/5" />
                          </div>
                          <div className="grid grid-cols-1 gap-4">
                            {rules.filter(r => r.category === cat).map(r => (
                              <div key={r.id} className="p-6 bg-[#141414] border border-white/5 rounded-2xl flex items-center justify-between gap-8 hover:shadow-md transition-all duration-300 group">
                                <div className="flex items-center gap-5">
                                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center transition-colors ${r.enabled ? 'bg-[#d97757]/10 text-[#d97757]' : 'bg-white/5 text-[#a3a3a3]'}`}>
                                    {cat === 'Filesystem' ? <FileText size={20} /> : cat === 'Database' ? <Database size={20} /> : <Network size={20} />}
                                  </div>
                                  <div>
                                    <div className="text-[15px] font-bold text-[#f5f5f5] tracking-tight">{r.name}</div>
                                    <div className="text-[12px] text-[#a3a3a3] mt-1 font-medium opacity-70">{r.description}</div>
                                  </div>
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

                {activeTab === 'compliance' && (
                  <div className="space-y-12">
                    <div className="flex items-baseline justify-between border-b border-white/5 pb-4">
                      <h2 className="text-2xl font-serif font-medium">Canadian Compliance</h2>
                      <span className="text-[10.5px] text-[#a3a3a3] uppercase tracking-widest font-bold">OSFI B-10/B-13 · PIPEDA · FINTRAC</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                      <section className="space-y-6">
                        <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">OSFI B-13 Technology Risk</h3>
                        <div className="bg-[#141414] border border-white/5 rounded-2xl p-8 shadow-sm space-y-6">
                          <div className="flex items-start gap-4">
                            <div className="w-10 h-10 rounded-xl bg-blue-900/20 flex items-center justify-center text-blue-400 shrink-0">
                              <Shield size={20} />
                            </div>
                            <div>
                              <div className="text-[14px] font-bold text-[#f5f5f5]">Cyber Resilience Guard</div>
                              <p className="text-[12px] text-[#a3a3a3] mt-1 leading-relaxed">
                                Monitoring for unauthorized system modifications and destructive patterns that threaten operational continuity in Canadian banking systems.
                              </p>
                            </div>
                          </div>
                          <div className="pt-4 border-t border-white/5">
                            <div className="flex justify-between items-center text-[11px]">
                              <span className="text-[#a3a3a3]">Compliance Status</span>
                              <Badge variant="info">Aligned</Badge>
                            </div>
                          </div>
                        </div>
                      </section>

                      <section className="space-y-6">
                        <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">PIPEDA Data Privacy</h3>
                        <div className="bg-[#141414] border border-white/5 rounded-2xl p-8 shadow-sm space-y-6">
                          <div className="flex items-start gap-4">
                            <div className="w-10 h-10 rounded-xl bg-orange-900/20 flex items-center justify-center text-orange-400 shrink-0">
                              <Eye size={20} />
                            </div>
                            <div>
                              <div className="text-[14px] font-bold text-[#f5f5f5]">PII Interception</div>
                              <p className="text-[12px] text-[#a3a3a3] mt-1 leading-relaxed">
                                Real-time masking of Social Insurance Numbers (SIN), health cards, and other sensitive Canadian identifiers across all agentic workflows.
                              </p>
                            </div>
                          </div>
                          <div className="pt-4 border-t border-white/5">
                            <div className="flex justify-between items-center text-[11px]">
                              <span className="text-[#a3a3a3]">Privacy Rating</span>
                              <Badge variant="info">High</Badge>
                            </div>
                          </div>
                        </div>
                      </section>
                    </div>

                    <section className="space-y-6">
                      <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#6b6b6b] font-bold opacity-60">Data Sovereignty & Residency</h3>
                      <div className="bg-[#0a0a0a] border border-black/20 rounded-2xl p-8 shadow-2xl ring-1 ring-white/5 overflow-hidden relative">
                        <div className="absolute top-0 right-0 p-8 opacity-10">
                          <Globe size={120} className="text-white" />
                        </div>
                        <div className="relative z-10 space-y-6">
                          <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center text-white border border-white/10">
                              <Globe size={24} />
                            </div>
                            <div>
                              <div className="text-lg font-bold text-white tracking-tight">Canadian Data Residency Guard</div>
                              <div className="text-[12px] text-white/40 uppercase tracking-widest font-bold">Active Enforcement</div>
                            </div>
                          </div>
                          <p className="text-white/60 text-[14px] leading-relaxed max-w-2xl">
                            BastionAudit monitors all outbound network requests from agentic tools to ensure sensitive financial data remains within Canadian cloud regions. Any attempt to exfiltrate data to non-compliant jurisdictions is automatically intercepted.
                          </p>
                          <div className="flex gap-4">
                            <div className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-[11px] text-white/80 font-bold">
                              Region: ca-central-1
                            </div>
                            <div className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-[11px] text-white/80 font-bold">
                              Latency: &lt; 2ms
                            </div>
                          </div>
                        </div>
                      </div>
                    </section>
                  </div>
                )}
                {activeTab === 'engine' && (
                  <div className="space-y-12">
                    <div className="flex items-baseline justify-between border-b border-white/5 pb-4">
                      <h2 className="text-2xl font-serif font-medium">Security Engine</h2>
                      <span className="text-[10.5px] text-[#a3a3a3] uppercase tracking-widest font-bold">Bastion Core v2.4.1 · Low-Latency Mode</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <StatCard label="P99 Latency" value="4.2ms" color="text-[#3ddc84]" />
                      <StatCard label="Throughput" value="1.2GB/s" color="text-blue-500" />
                      <StatCard label="Memory Footprint" value="12.4MB" color="text-[#d97757]" />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                      <section className="space-y-6">
                        <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">Engine Configuration</h3>
                        <div className="bg-[#141414] border border-white/5 rounded-2xl p-8 shadow-sm space-y-6">
                          <div className="space-y-4">
                            <div className="flex items-center justify-between">
                              <span className="text-[13px] font-bold text-[#f5f5f5]">Scan Intensity</span>
                              <Badge variant={scanIntensity === 'HIGH_PRECISION' ? 'info' : 'high'}>
                                {scanIntensity === 'HIGH_PRECISION' ? 'Deep Analysis' : 'Turbo Mode'}
                              </Badge>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                              <button 
                                onClick={() => setScanIntensity('HIGH_PRECISION')}
                                className={`p-4 rounded-xl border-2 transition-all text-left group ${scanIntensity === 'HIGH_PRECISION' ? 'border-[#d97757] bg-[#d97757]/5' : 'border-white/5 hover:border-white/10'}`}
                              >
                                <div className={`text-[12px] font-bold mb-1 ${scanIntensity === 'HIGH_PRECISION' ? 'text-[#d97757]' : 'text-[#f5f5f5]'}`}>High Precision</div>
                                <div className="text-[10px] text-[#a3a3a3] leading-relaxed">Maximum depth, multi-pass entropy checks.</div>
                              </button>
                              <button 
                                onClick={() => setScanIntensity('MAX_SPEED')}
                                className={`p-4 rounded-xl border-2 transition-all text-left group ${scanIntensity === 'MAX_SPEED' ? 'border-[#d97757] bg-[#d97757]/5' : 'border-white/5 hover:border-white/10'}`}
                              >
                                <div className={`text-[12px] font-bold mb-1 ${scanIntensity === 'MAX_SPEED' ? 'text-[#d97757]' : 'text-[#f5f5f5]'}`}>Max Speed</div>
                                <div className="text-[10px] text-[#a3a3a3] leading-relaxed">Optimized for low-latency, single-pass scan.</div>
                              </button>
                            </div>
                          </div>

                          <div className="pt-4 border-t border-white/5 space-y-4">
                            <div className="flex justify-between items-center">
                              <span className="text-[11px] text-[#a3a3a3]">Expected Latency</span>
                              <span className="text-[11px] font-mono font-bold text-[#f5f5f5]">
                                {scanIntensity === 'HIGH_PRECISION' ? '~8.5ms' : '< 1.2ms'}
                              </span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-[11px] text-[#a3a3a3]">Detection Sensitivity</span>
                              <span className="text-[11px] font-bold text-[#f5f5f5]">
                                {scanIntensity === 'HIGH_PRECISION' ? 'Ultra (99.9%)' : 'Standard (94%)'}
                              </span>
                            </div>
                          </div>
                        </div>

                        <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">Performance Metrics</h3>
                        <div className="bg-[#141414] border border-white/5 rounded-2xl p-8 shadow-sm space-y-8">
                          <div className="space-y-4">
                            <div className="flex justify-between items-end">
                              <span className="text-[12px] font-bold text-[#f5f5f5]">Scan Latency Distribution</span>
                              <span className="text-[10px] text-[#a3a3a3] font-mono">Real-time (Last 60s)</span>
                            </div>
                            <div className="h-24 flex items-end gap-1">
                              {[40, 35, 45, 30, 55, 40, 35, 60, 45, 50, 30, 40, 35, 45, 30, 55, 40, 35, 60, 45].map((h, i) => (
                                <motion.div 
                                  key={i}
                                  initial={{ height: 0 }}
                                  animate={{ height: `${h}%` }}
                                  transition={{ delay: i * 0.02 }}
                                  className={`flex-1 rounded-t-sm ${h > 50 ? 'bg-red-400/40' : 'bg-[#d97757]/40'}`}
                                />
                              ))}
                            </div>
                            <div className="flex justify-between text-[10px] text-[#a3a3a3] font-bold uppercase tracking-widest pt-2 border-t border-white/5">
                              <span>0ms</span>
                              <span>2.5ms</span>
                              <span>5.0ms</span>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-6">
                            <div className="p-4 bg-white/[0.02] rounded-xl border border-white/5">
                              <div className="text-[10px] text-[#a3a3a3] font-bold uppercase mb-1">CPU Usage</div>
                              <div className="text-xl font-serif font-bold text-[#f5f5f5]">0.8%</div>
                            </div>
                            <div className="p-4 bg-white/[0.02] rounded-xl border border-white/5">
                              <div className="text-[10px] text-[#a3a3a3] font-bold uppercase mb-1">Active Threads</div>
                              <div className="text-xl font-serif font-bold text-[#f5f5f5]">4</div>
                            </div>
                          </div>
                        </div>
                      </section>

                      <section className="space-y-6">
                        <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold opacity-60">Heuristic Analysis</h3>
                        <div className="bg-[#141414] border border-white/5 rounded-2xl p-8 shadow-sm space-y-6">
                          <div className="flex items-start gap-4">
                            <div className="w-10 h-10 rounded-xl bg-blue-900/20 flex items-center justify-center text-blue-400 shrink-0">
                              <Search size={20} />
                            </div>
                            <div>
                              <div className="text-[14px] font-bold text-[#f5f5f5]">Entropy-Based Detection</div>
                              <p className="text-[12px] text-[#a3a3a3] mt-1 leading-relaxed">
                                BastionAudit uses Shannon entropy calculations to identify high-randomness strings (API keys, secrets) that bypass traditional regex patterns.
                              </p>
                            </div>
                          </div>

                          <div className="flex items-start gap-4">
                            <div className="w-10 h-10 rounded-xl bg-orange-900/20 flex items-center justify-center text-orange-400 shrink-0">
                              <Database size={20} />
                            </div>
                            <div>
                              <div className="text-[14px] font-bold text-[#f5f5f5]">Semantic Interception</div>
                              <p className="text-[12px] text-[#a3a3a3] mt-1 leading-relaxed">
                                Beyond simple string matching, the engine analyzes command context to detect destructive patterns like <code className="bg-white/10 px-1 rounded">rm -rf /</code> or unauthorized database exfiltration.
                              </p>
                            </div>
                          </div>

                          <div className="pt-4 border-t border-white/5">
                            <div className="flex items-center justify-between mb-3">
                              <span className="text-[11px] font-bold text-[#f5f5f5]">Engine Health</span>
                              <Badge variant="info">Optimized</Badge>
                            </div>
                            <div className="space-y-2">
                              <div className="flex justify-between text-[11px]">
                                <span className="text-[#a3a3a3]">Uptime</span>
                                <span className="text-[#f5f5f5] font-mono">14d 06h 22m</span>
                              </div>
                              <div className="flex justify-between text-[11px]">
                                <span className="text-[#a3a3a3]">Last Pattern Sync</span>
                                <span className="text-[#f5f5f5]">2026-03-22 09:14 UTC</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      </section>
                    </div>

                    <section className="space-y-6">
                      <h3 className="text-[11px] uppercase tracking-[0.2em] text-[#6b6b6b] font-bold opacity-60">Integration Status</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <IntegrationItem name="Claude Code" status="Connected" icon={<Terminal size={14} />} />
                        <IntegrationItem name="GKE Cluster" status="Active" icon={<Network size={14} />} />
                        <IntegrationItem name="GitHub Actions" status="Standby" icon={<Activity size={14} />} />
                        <IntegrationItem name="Slack Alerts" status="Connected" icon={<ExternalLink size={14} />} />
                      </div>
                    </section>
                  </div>
                )}

                {activeTab === 'log' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-white/5 pb-4">
                      <h2 className="text-2xl font-serif font-medium">Audit Log</h2>
                      <span className="text-[10.5px] text-[#a3a3a3] uppercase tracking-widest font-bold">SECURITY_AUDIT.md · session 2026-03-22</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <StatCard label="Open incidents" value="1" color="text-red-500" />
                      <StatCard label="Resolved" value="7" color="text-[#3ddc84]" />
                      <StatCard label="Log size" value="7.2KB" color="text-[#d97757]" />
                    </div>

                    <section className="space-y-4">
                      <h3 className="text-[10px] uppercase tracking-widest text-[#a3a3a3] font-bold">Recent Events</h3>
                      <div className="space-y-1">
                        <LogEntry id="INC-001" type="Write intercept" path="/etc/cron.d" time="14:07:33" severity="CRITICAL" status="OPEN" />
                        <LogEntry id="INC-002" type="SSN detected" path="env var" time="11:22:14" severity="HIGH" status="DONE" />
                        <LogEntry id="INC-003" type="rm -rf on prod" path="/var/www" time="10:14:08" severity="CRITICAL" status="DONE" />
                      </div>
                    </section>
                  </div>
                )}

                {activeTab === 'plugin-files' && (
                  <div className="space-y-8">
                    <div className="flex items-baseline justify-between border-b border-white/5 pb-4">
                      <h2 className="text-2xl font-serif font-medium">Plugin Files</h2>
                      <span className="text-[10.5px] text-[#6b6b6b] uppercase tracking-widest font-bold">Generated artifacts for Claude Code</span>
                    </div>

                    <div className="grid grid-cols-1 gap-8">
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
            <Footer />
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
            className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-[#1a1a1a]/40 backdrop-blur-sm"
          >
            <motion.div 
              initial={{ scale: 0.95, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.95, y: 20 }}
              className="w-full max-w-[700px] bg-[#141414] border border-red-900/30 rounded-2xl overflow-hidden shadow-2xl"
            >
              <div className="bg-[#1c1c1c] border-b border-white/5 p-4 px-6 flex items-center gap-3">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
                </div>
                <span className="text-[10px] text-[#a3a3a3] uppercase tracking-widest mx-auto font-bold">safe-code-audit — zsh — /workspace</span>
              </div>

              <div className="p-8 border-l-[4px] border-red-500 bg-red-950/10">
                <div className="flex items-center gap-4 mb-6">
                  <div className="bg-red-500 text-white text-[10px] font-bold tracking-widest px-3 py-1 rounded-full shadow-lg shadow-red-500/20">
                    INTERCEPT
                  </div>
                  <h3 className="text-red-500 font-serif font-bold text-lg tracking-tight">Bastion Audit Alert</h3>
                  <span className="ml-auto text-[11px] text-[#a3a3a3] font-medium">2026-03-22 · 14:07:33 UTC</span>
                </div>

                <div className="grid grid-cols-2 gap-x-12 gap-y-2 text-[12px]">
                  <div className="flex justify-between border-b border-white/5 pb-1"><span className="text-[#a3a3a3]">Session ID</span><span className="text-[#f5f5f5] font-mono">BA-20260322-9F3A</span></div>
                  <div className="flex justify-between border-b border-white/5 pb-1"><span className="text-[#a3a3a3]">Tool type</span><span className="text-red-500 font-bold">Write / Bash</span></div>
                  <div className="flex justify-between border-b border-white/5 pb-1"><span className="text-[#a3a3a3]">Target path</span><span className="text-orange-500 font-medium">/etc/cron.d/backup</span></div>
                  <div className="flex justify-between border-b border-white/5 pb-1"><span className="text-[#a3a3a3]">Environment</span><span className="text-[#f5f5f5]">prod-gke-cluster</span></div>
                </div>

                <div className="mt-8">
                  <div className="text-[#a3a3a3] font-bold text-[10px] uppercase tracking-widest mb-3">▸ Threat Analysis</div>
                  <div className="bg-[#1c1c1c] border border-red-900/20 p-5 rounded-xl shadow-sm">
                    <div className="flex items-center gap-3 mb-3">
                      <Badge variant="crit">Critical</Badge>
                      <span className="text-red-400 font-bold text-[14px]">Privileged write to system crontab</span>
                    </div>
                    <div className="space-y-2 text-[12px]">
                      <div className="flex gap-4"><span className="w-24 text-[#a3a3a3]">Matched rule</span><span className="text-[#f5f5f5]">RULE-SYS-0091 · CIS Linux 5.1.3</span></div>
                      <div className="flex gap-4"><span className="w-24 text-[#a3a3a3]">Pattern</span><span className="text-orange-400">write → /etc/cron* · root escalation</span></div>
                      <div className="flex gap-4"><span className="w-24 text-[#a3a3a3]">Risk vector</span><span className="text-red-400 font-medium">Persistence · privilege escalation</span></div>
                    </div>
                  </div>
                </div>

                <div className="mt-8">
                  <div className="text-[#a3a3a3] font-bold text-[10px] uppercase tracking-widest mb-3">▸ Severity</div>
                  <div className="flex gap-1.5 mb-3">
                    {[1,2,3,4,5].map(i => <div key={i} className="h-2.5 flex-1 bg-red-500 rounded-full" />)}
                    {[6,7,8,9,10].map(i => <div key={i} className="h-2.5 flex-1 bg-white/5 rounded-full" />)}
                  </div>
                  <div className="text-[11px] text-[#a3a3a3]">CRITICAL 5/10 · Regulatory exposure: SOC2 CC6.2 · estimated $80K–$2M impact</div>
                </div>

                <div className="mt-8">
                  <div className="text-[#a3a3a3] font-bold text-[10px] uppercase tracking-widest mb-3">▸ Action Required</div>
                  <div className="bg-blue-950/20 border border-blue-900/30 p-5 rounded-xl space-y-3">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="info">Remediation available</Badge>
                    </div>
                    <RemediationStep n={1} text={<>Use <span className="text-blue-400 font-medium">systemd timers</span> instead of crontab for auditable scheduling</>} />
                    <RemediationStep n={2} text={<>Write backup output to <span className="text-blue-400 font-medium">/secure/backups/</span> with strict 0600 permissions</>} />
                    <RemediationStep n={3} text={<>Run backup process under dedicated <span className="text-blue-400 font-medium">backup-svc</span> user, not root</>} />
                  </div>
                </div>

                <div className="mt-10 pt-6 border-t border-white/5">
                  <div className="text-[#f5f5f5] font-bold mb-5 text-[14px]">Command blocked. Select an action:</div>
                  <div className="flex flex-wrap gap-4">
                    <button onClick={() => handleAlertAction('ABORT')} className="flex-1 px-6 py-3 rounded-xl bg-red-600 text-white font-bold text-[12px] tracking-widest hover:bg-red-700 transition-all uppercase shadow-lg shadow-red-600/20">Abort Command</button>
                    <button onClick={() => handleAlertAction('MASK')} className="flex-1 px-6 py-3 rounded-xl border border-orange-900/50 bg-orange-950/30 text-orange-400 font-bold text-[12px] tracking-widest hover:bg-orange-900/50 transition-all uppercase">Mask & Remediate</button>
                    <button onClick={() => handleAlertAction('REVIEW')} className="flex-1 px-6 py-3 rounded-xl border border-white/10 text-[#a3a3a3] font-bold text-[12px] tracking-widest hover:bg-white/5 transition-all uppercase">Review Manually</button>
                  </div>
                  <div className="mt-6 text-[11px] text-[#a3a3a3] flex justify-between items-center">
                    <span>Auto-abort in <span className="text-red-500 font-bold">{countdown}</span>s</span>
                    <span className="font-mono">Ref: BA-20260322-9F3A</span>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* --- Floating Chat Assistant --- */}
      <div className="fixed bottom-8 right-8 z-50">
        <AnimatePresence>
          {isChatOpen && (
            <motion.div
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="absolute bottom-20 right-0 w-[400px] h-[550px] bg-[#141414] border border-white/10 rounded-3xl shadow-2xl flex flex-col overflow-hidden"
            >
              <div className="bg-[#d97757] p-6 text-white flex items-center justify-between shadow-lg">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-white/20 flex items-center justify-center">
                    <MessageSquare size={20} />
                  </div>
                  <div>
                    <div className="text-[14px] font-bold tracking-tight">BastionAudit AI</div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <div className="text-[9px] uppercase tracking-widest font-bold opacity-70">
                        {useGemini ? 'Gemini 3.1 Pro' : 'Claude 3.5 Sonnet'}
                      </div>
                      <button 
                        onClick={() => setUseGemini(!useGemini)}
                        className="px-1.5 py-0.5 rounded bg-white/10 hover:bg-white/20 text-[8px] font-bold uppercase tracking-tighter transition-colors"
                      >
                        Switch to {useGemini ? 'Claude' : 'Gemini'}
                      </button>
                    </div>
                  </div>
                </div>
                <button onClick={() => setIsChatOpen(false)} className="hover:bg-white/10 p-2 rounded-lg transition-colors">
                  <ChevronRight size={20} className="rotate-90" />
                </button>
              </div>
              
              <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-[#0d0d0d]">
                {chatMessages.length === 0 && (
                  <div className="h-full flex flex-col items-center justify-center text-center space-y-4 opacity-40">
                    <Shield size={48} className="text-[#d97757]" />
                    <p className="text-[13px] font-medium max-w-[200px] text-[#a3a3a3]">
                      Ask me about OSFI B-13 compliance, PIPEDA data privacy, or Canadian data residency.
                    </p>
                  </div>
                )}
                {chatMessages.map((m, i) => (
                  <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[85%] p-4 rounded-2xl text-[13px] leading-relaxed ${m.role === 'user' ? 'bg-[#d97757] text-white rounded-tr-none shadow-md' : 'bg-[#1c1c1c] border border-white/5 text-[#f5f5f5] rounded-tl-none shadow-sm'}`}>
                      {m.content}
                    </div>
                  </div>
                ))}
                {isChatLoading && (
                  <div className="flex justify-start">
                    <div className="bg-[#1c1c1c] border border-white/5 p-4 rounded-2xl rounded-tl-none shadow-sm flex gap-2">
                      <div className="w-1.5 h-1.5 bg-[#d97757] rounded-full animate-bounce" />
                      <div className="w-1.5 h-1.5 bg-[#d97757] rounded-full animate-bounce [animation-delay:0.2s]" />
                      <div className="w-1.5 h-1.5 bg-[#d97757] rounded-full animate-bounce [animation-delay:0.4s]" />
                    </div>
                  </div>
                )}
              </div>

              <form onSubmit={handleSendMessage} className="p-4 bg-[#141414] border-t border-white/5 flex gap-3">
                <input 
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="Ask the security assistant..."
                  className="flex-1 bg-white/[0.03] border-none outline-none rounded-xl px-4 py-3 text-[13px] font-medium text-[#f5f5f5] placeholder:text-[#a3a3a3]/40"
                />
                <button 
                  type="submit"
                  disabled={isChatLoading}
                  className="w-11 h-11 bg-[#d97757] text-white rounded-xl flex items-center justify-center hover:bg-[#b45309] transition-colors disabled:opacity-50 shadow-md"
                >
                  <Send size={18} />
                </button>
              </form>
            </motion.div>
          )}
        </AnimatePresence>

        <button 
          onClick={() => setIsChatOpen(!isChatOpen)}
          className={`w-16 h-16 rounded-full flex items-center justify-center shadow-2xl transition-all duration-500 transform hover:scale-110 ${isChatOpen ? 'bg-white text-[#d97757] rotate-90' : 'bg-[#d97757] text-white'}`}
        >
          {isChatOpen ? <ChevronRight size={24} /> : <MessageSquare size={24} />}
        </button>
      </div>

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
      className={`w-full flex items-center gap-4 px-8 py-3.5 text-[13px] transition-all border-l-[3px] group ${active ? 'text-[#f5f5f5] bg-[#d97757]/10 border-[#d97757] font-bold' : 'text-[#a3a3a3] border-transparent hover:text-[#f5f5f5] hover:bg-white/[0.02]'}`}
    >
      <div className={`transition-transform duration-300 group-hover:scale-110 ${active ? 'text-[#d97757]' : 'text-[#a3a3a3]'}`}>{icon}</div>
      {label}
    </button>
  );
}

function StatCard({ label, value, color }: { label: string, value: string, color: string }) {
  return (
    <div className="bg-[#141414] border border-white/5 rounded-2xl p-8 shadow-[0_4px_20px_rgba(0,0,0,0.2)] hover:shadow-[0_8px_30px_rgba(0,0,0,0.3)] transition-all duration-300 group">
      <div className="text-[10px] uppercase tracking-[0.2em] text-[#a3a3a3] font-bold mb-4 opacity-60 group-hover:opacity-100 transition-opacity">{label}</div>
      <div className={`text-4xl font-serif font-bold tracking-tight ${color}`}>{value}</div>
      <div className="mt-4 h-1 w-8 bg-white/5 rounded-full overflow-hidden">
        <div className={`h-full w-2/3 ${color.replace('text-', 'bg-')} opacity-40`} />
      </div>
    </div>
  );
}

function LogEntry({ id, type, path, time, severity, status }: any) {
  return (
    <div className="flex items-center justify-between py-4 border-b border-white/5 group hover:bg-white/[0.02] cursor-pointer transition-colors">
      <div>
        <div className={`text-[13px] font-medium ${severity === 'CRITICAL' ? 'text-red-500' : 'text-amber-500'}`}>
          {id} · {type} · {path}
        </div>
        <div className="text-[11px] text-[#a3a3a3] mt-1">
          {time} · {severity} · {status === 'OPEN' ? 'Pending review' : 'Resolved'}
        </div>
      </div>
      <span className={`text-[10px] font-bold tracking-widest px-2 py-1 rounded border ${status === 'OPEN' ? 'text-red-400 border-red-900/50 bg-red-950/30' : 'text-[#3ddc84] border-green-900/50 bg-green-950/30'}`}>
        {status}
      </span>
    </div>
  );
}

function RemediationStep({ n, text }: { n: number, text: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-[12px] text-[#a3a3a3]">
      <span className="text-[#f5f5f5] font-medium">{n}.</span>
      <span>{text}</span>
    </div>
  );
}

function IntegrationItem({ name, status, icon }: { name: string, status: string, icon: React.ReactNode }) {
  return (
    <div className="bg-[#141414] border border-white/5 rounded-xl p-4 flex items-center justify-between shadow-sm hover:shadow-md transition-all duration-300">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-white/[0.03] flex items-center justify-center text-[#a3a3a3]">
          {icon}
        </div>
        <span className="text-[12px] font-bold text-[#f5f5f5]">{name}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <div className={`w-1.5 h-1.5 rounded-full ${status === 'Active' || status === 'Connected' ? 'bg-[#3ddc84]' : 'bg-amber-400'}`} />
        <span className="text-[10px] font-bold text-[#a3a3a3] uppercase tracking-wider">{status}</span>
      </div>
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
    <div className="bg-[#141414] border border-white/5 rounded-xl overflow-hidden shadow-sm">
      <div className="bg-[#1c1c1c] border-b border-white/5 px-5 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText size={16} className="text-[#a3a3a3]" />
          <span className="text-[12px] font-bold text-[#f5f5f5]">{name}</span>
          <span className="text-[11px] text-[#a3a3a3] font-normal">{path}</span>
        </div>
        <div className="flex gap-2">
          <button onClick={copy} className="p-1.5 text-[#a3a3a3] hover:text-[#f5f5f5] transition-colors relative">
            {copied ? <CheckCircle2 size={16} className="text-[#3ddc84]" /> : <Copy size={16} />}
          </button>
        </div>
      </div>
      <pre className="p-6 text-[12px] text-[#f5f5f5] overflow-x-auto bg-[#0d0d0d] font-mono leading-relaxed">
        <code>{content}</code>
      </pre>
    </div>
  );
}

function Footer() {
  return (
    <footer className="bg-[#0a0a0a] border-t border-white/5 py-16 px-8 mt-20">
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-12">
        <div className="col-span-1 md:col-span-1 space-y-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#d97757] flex items-center justify-center text-white shadow-lg shadow-[#d97757]/20">
              <Shield size={20} />
            </div>
            <span className="text-[18px] font-serif font-bold tracking-tight text-[#f5f5f5]">BastionAudit</span>
          </div>
          <p className="text-[13px] text-[#a3a3a3] leading-relaxed max-w-[240px]">
            Advanced security auditing and compliance for the Canadian financial services industry. 
            Trusted by Canada's Big Five banks.
          </p>
          <div className="flex items-center gap-4 text-[#a3a3a3]">
            <Award size={18} className="text-[#d97757]" />
            <span className="text-[11px] font-bold uppercase tracking-widest">OSFI Compliant</span>
          </div>
        </div>

        <div className="space-y-6">
          <h4 className="text-[11px] uppercase tracking-[0.2em] text-[#f5f5f5] font-bold">Canadian Compliance</h4>
          <ul className="space-y-4 text-[13px] text-[#a3a3a3]">
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <ChevronRight size={14} /> OSFI B-10 Third-Party Risk
            </li>
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <ChevronRight size={14} /> OSFI B-13 Technology Risk
            </li>
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <ChevronRight size={14} /> PIPEDA Data Privacy
            </li>
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <ChevronRight size={14} /> FINTRAC AML Compliance
            </li>
          </ul>
        </div>

        <div className="space-y-6">
          <h4 className="text-[11px] uppercase tracking-[0.2em] text-[#f5f5f5] font-bold">Financial Services</h4>
          <ul className="space-y-4 text-[13px] text-[#a3a3a3]">
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <Globe size={14} /> Canadian Data Residency
            </li>
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <Lock size={14} /> SOC2 Type II Certification
            </li>
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <Activity size={14} /> Real-time Audit Logging
            </li>
            <li className="hover:text-[#d97757] cursor-pointer transition-colors flex items-center gap-2">
              <ExternalLink size={14} /> GKE Security Clusters
            </li>
          </ul>
        </div>

        <div className="space-y-6">
          <h4 className="text-[11px] uppercase tracking-[0.2em] text-[#f5f5f5] font-bold">Resources</h4>
          <div className="bg-[#141414] border border-white/5 rounded-2xl p-6 shadow-sm">
            <p className="text-[12px] text-[#a3a3a3] leading-relaxed mb-4">
              Need help with your OSFI B-13 audit? Our security experts are available 24/7.
            </p>
            <button className="w-full py-2.5 bg-[#f5f5f5] text-[#0a0a0a] text-[11px] font-bold uppercase tracking-widest rounded-xl hover:bg-white transition-colors">
              Contact Support
            </button>
          </div>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto mt-16 pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-6">
        <div className="text-[11px] text-[#a3a3a3] font-medium">
          © 2026 BastionAudit Security. All rights reserved. Registered in Toronto, ON.
        </div>
        <div className="flex gap-8 text-[11px] text-[#a3a3a3] font-bold uppercase tracking-widest">
          <span className="hover:text-[#f5f5f5] cursor-pointer transition-colors">Privacy Policy</span>
          <span className="hover:text-[#f5f5f5] cursor-pointer transition-colors">Terms of Service</span>
          <span className="hover:text-[#f5f5f5] cursor-pointer transition-colors">Security Disclosure</span>
        </div>
      </div>
    </footer>
  );
}
