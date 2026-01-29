
import React, { useState, useEffect } from 'react';
import { X, HardDrive, Radio, Activity, Lock, Wifi, Zap, FileText, Share2, AlertOctagon, Terminal, Server, ExternalLink, ShieldAlert, ShieldCheck } from 'lucide-react';
import { AreaChart, Area, Tooltip, ResponsiveContainer, YAxis } from 'recharts';
import { Node, Connection } from '../types';

interface InspectorPanelProps {
  selectedNode: Node;
  nodes: Node[];
  connections: Connection[];
  hoveredConnection: string | null;
  setHoveredConnection: (id: string | null) => void;
  onClose: () => void;
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="rounded border border-white/10 bg-black/90 p-2 shadow-[0_0_15px_rgba(0,0,0,0.5)] backdrop-blur-md">
        <p className="mb-1 font-mono text-[9px] font-bold text-slate-500 uppercase tracking-widest">
          T-{30 - label}s
        </p>
        <p className="font-mono text-xs font-bold text-white">
          <span className="mr-1 text-cyan-400">►</span>
          {Number(payload[0].value).toFixed(1)} <span className="text-[9px] text-slate-400">MB/s</span>
        </p>
      </div>
    );
  }
  return null;
};

const TrafficGraph = ({ value, color }: { value: number; color: string }) => {
  const [data, setData] = useState<number[]>(Array(30).fill(value));

  useEffect(() => {
    setData(prev => {
      const newData = [...prev, value];
      if (newData.length > 30) newData.shift();
      return newData;
    });
  }, [value]);

  const chartData = data.map((val, i) => ({ index: i, value: val }));

  return (
    <div className="relative h-16 w-full overflow-hidden rounded bg-black/40 border border-white/5">
       {/* Overlay Effects */}
       <div className="pointer-events-none absolute inset-0 flex flex-col justify-between py-1 opacity-10 z-10">
         <div className="border-t border-dashed border-white"></div>
         <div className="border-t border-dashed border-white"></div>
         <div className="border-t border-dashed border-white"></div>
       </div>

       <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id={`grad-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.4}/>
                <stop offset="95%" stopColor={color} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(255,255,255,0.1)', strokeWidth: 1 }} />
            <YAxis domain={[0, 100]} hide />
            <Area 
              type="monotone" 
              dataKey="value" 
              stroke={color} 
              fillOpacity={1} 
              fill={`url(#grad-${color.replace('#', '')})`} 
              strokeWidth={2}
              isAnimationActive={false}
            />
          </AreaChart>
       </ResponsiveContainer>
    </div>
  );
};

export const InspectorPanel: React.FC<InspectorPanelProps> = ({ 
  selectedNode, nodes, connections, hoveredConnection, setHoveredConnection, onClose 
}) => {
  const [activeTab, setActiveTab] = useState<'details' | 'connections' | 'traffic'>('details');
  
  const nodeConnections = connections.filter(c => c.from === selectedNode.id || c.to === selectedNode.id);

  const hasVulnerabilities = (selectedNode.detailedVulnerabilities && selectedNode.detailedVulnerabilities.length > 0) || 
                             (selectedNode.vulnerabilities && selectedNode.vulnerabilities.length > 0);

  const getSeverityColor = (severity: string) => {
    switch(severity.toLowerCase()) {
      case 'critical': return 'bg-red-500 text-white shadow-[0_0_10px_rgba(239,68,68,0.5)]';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black font-bold';
      case 'low': return 'bg-blue-500 text-white';
      default: return 'bg-slate-500 text-white';
    }
  };

  return (
    <div className="z-30 w-80 border-l border-white/10 bg-black/90 backdrop-blur-md flex flex-col h-full transition-all duration-300">
       {/* HEADER */}
       <div className="p-6 pb-0 flex-shrink-0 bg-black/40">
           <div className="flex items-start justify-between mb-6">
              <div>
                <div className="flex items-center gap-2 mb-1">
                   <div className={`h-2 w-2 rounded-full ${
                     selectedNode.status === 'compromised' ? 'bg-red-500 animate-ping' :
                     selectedNode.status === 'warning' ? 'bg-amber-500' :
                     selectedNode.status === 'online' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]' : 
                     'bg-slate-500'
                   }`} />
                   <h2 className={`text-xl font-bold uppercase leading-none truncate w-48 ${selectedNode.status === 'compromised' ? 'text-red-500' : 'text-white'}`}>
                     {selectedNode.label}
                   </h2>
                </div>
                <div className="text-[10px] text-cyan-500 font-black uppercase tracking-[0.2em]">{selectedNode.type}</div>
              </div>
              <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors"><X size={18} /></button>
           </div>

           {/* TABS */}
           <div className="flex border-b border-white/10">
              <button 
                onClick={() => setActiveTab('details')}
                className={`flex-1 flex items-center justify-center gap-2 py-3 text-[10px] font-bold uppercase tracking-wider transition-colors border-b-2 ${activeTab === 'details' ? 'border-cyan-500 text-cyan-400 bg-cyan-500/5' : 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
              >
                <FileText size={12} /> Details
              </button>
              <button 
                onClick={() => setActiveTab('connections')}
                className={`flex-1 flex items-center justify-center gap-2 py-3 text-[10px] font-bold uppercase tracking-wider transition-colors border-b-2 ${activeTab === 'connections' ? 'border-cyan-500 text-cyan-400 bg-cyan-500/5' : 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
              >
                <Share2 size={12} /> Links
              </button>
              <button 
                onClick={() => setActiveTab('traffic')}
                className={`flex-1 flex items-center justify-center gap-2 py-3 text-[10px] font-bold uppercase tracking-wider transition-colors border-b-2 ${activeTab === 'traffic' ? 'border-cyan-500 text-cyan-400 bg-cyan-500/5' : 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
              >
                <Activity size={12} /> Traffic
              </button>
           </div>
       </div>

       {/* CONTENT AREA */}
       <div className="flex-1 overflow-y-auto p-6 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
          
          {activeTab === 'details' && (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                {/* VULNERABILITY ALERT */}
                {selectedNode.status === 'compromised' && (
                  <div className="rounded border border-red-500/30 bg-red-900/20 p-4">
                     <div className="flex items-center gap-2 text-red-500 mb-2">
                        <AlertOctagon size={16} />
                        <span className="text-xs font-black uppercase tracking-widest">Security Breach</span>
                     </div>
                     <div className="text-[10px] text-red-200">
                        Target has been successfully exploited. Full administrative access granted.
                     </div>
                  </div>
                )}

                {/* DETAILED VULNERABILITIES */}
                {hasVulnerabilities ? (
                  <div className="space-y-3">
                    <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                      <ShieldAlert size={12} /> Detected Vulnerabilities
                    </h3>
                    
                    {selectedNode.detailedVulnerabilities && selectedNode.detailedVulnerabilities.map((vuln, idx) => (
                      <div key={idx} className="rounded border border-white/10 bg-white/5 p-3 hover:bg-white/10 transition-colors">
                        <div className="flex items-start justify-between mb-2">
                           <div className="flex items-center gap-2">
                              <span className="text-xs font-bold text-white">{vuln.cve}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase tracking-wider ${getSeverityColor(vuln.severity)}`}>
                                {vuln.severity}
                              </span>
                           </div>
                           <span className={`text-xs font-mono font-bold ${
                              vuln.cvss >= 9 ? 'text-red-500' : vuln.cvss >= 7 ? 'text-orange-500' : 'text-yellow-500'
                           }`}>CVSS {vuln.cvss}</span>
                        </div>
                        <p className="text-[9px] text-slate-400 leading-relaxed mb-2">
                          {vuln.description}
                        </p>
                        {vuln.references && (
                           <div className="flex flex-wrap gap-2">
                             {vuln.references.map((ref, i) => (
                               <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-[8px] text-cyan-400 hover:text-cyan-300 hover:underline">
                                  <ExternalLink size={8} /> Ref {i+1}
                               </a>
                             ))}
                           </div>
                        )}
                      </div>
                    ))}
                    
                    {/* Fallback for legacy vulnerabilities list */}
                    {(!selectedNode.detailedVulnerabilities || selectedNode.detailedVulnerabilities.length === 0) && selectedNode.vulnerabilities && (
                      <div className="space-y-1">
                        {selectedNode.vulnerabilities.map(v => (
                          <div key={v} className="bg-white/5 border border-white/10 px-2 py-1.5 rounded text-slate-300 font-mono text-[10px] flex justify-between items-center">
                            <span>{v}</span>
                            <span className="text-[8px] bg-slate-700 px-1 rounded text-white">UNKNOWN</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  // Empty State
                  <div className="flex flex-col items-center justify-center p-8 rounded border border-dashed border-white/10 text-slate-600 gap-3">
                     <ShieldCheck size={32} className="opacity-50" />
                     <span className="text-[10px] uppercase font-bold tracking-widest text-center">No Vulnerabilities Detected</span>
                  </div>
                )}

                {/* API EXTENDED DETAILS */}
                {selectedNode.apiData && (
                  <div className="rounded border border-white/5 bg-white/5 p-4 space-y-2">
                    <div className="flex justify-between text-[10px] uppercase">
                       <span className="text-slate-500 font-bold">OS Family</span>
                       <span className="text-cyan-400 font-mono">{selectedNode.apiData.os_family || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between text-[10px] uppercase">
                       <span className="text-slate-500 font-bold">First Seen</span>
                       <span className="text-slate-300 font-mono text-[9px]">{new Date(selectedNode.apiData.first_seen).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between text-[10px] uppercase">
                       <span className="text-slate-500 font-bold">Last Seen</span>
                       <span className="text-slate-300 font-mono text-[9px]">{new Date(selectedNode.apiData.last_seen).toLocaleTimeString()}</span>
                    </div>
                  </div>
                )}

                {/* PORTS */}
                {(selectedNode.ports || (selectedNode.apiData?.ports && selectedNode.apiData.ports.length > 0)) && (
                  <div className="rounded border border-white/5 bg-white/5 p-4">
                     <div className="flex items-center gap-2 text-emerald-400 mb-2">
                        <Terminal size={14} />
                        <span className="text-[10px] font-black uppercase tracking-widest">Open Ports</span>
                     </div>
                     
                     {selectedNode.apiData?.ports ? (
                       <div className="space-y-2">
                          {selectedNode.apiData.ports.map(port => (
                            <div key={port.id} className="flex flex-col bg-emerald-500/5 border border-emerald-500/20 rounded p-2">
                              <div className="flex justify-between items-center mb-1">
                                <span className="text-xs font-mono text-emerald-400 font-bold">{port.port_number}/{port.protocol}</span>
                                <span className="text-[8px] bg-emerald-500/20 px-1 rounded text-emerald-300 uppercase">{port.state}</span>
                              </div>
                              <div className="text-[9px] text-slate-400 font-mono truncate">{port.service_name} {port.service_version}</div>
                            </div>
                          ))}
                       </div>
                     ) : (
                       <div className="grid grid-cols-3 gap-2">
                          {selectedNode.ports?.map(port => (
                            <div key={port} className="bg-emerald-500/10 border border-emerald-500/20 rounded px-2 py-1 text-center">
                              <span className="text-xs font-mono text-emerald-400">{port}</span>
                            </div>
                          ))}
                       </div>
                     )}
                  </div>
                )}

                {/* BRAND IDENTIFICATION */}
                {selectedNode.vendor && (
                  <div className="rounded border-l-4 border-cyan-500 bg-cyan-500/5 p-4 flex items-center gap-4">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded bg-cyan-500/20 text-cyan-400">
                        <HardDrive size={20} />
                    </div>
                    <div>
                        <div className="text-[8px] font-black text-cyan-500/60 uppercase tracking-widest">Detected Hardware</div>
                        <div className="text-sm font-bold text-white">{selectedNode.vendor}</div>
                        {selectedNode.oui && (
                          <div className="text-[10px] text-cyan-400 font-mono mt-0.5">OUI: {selectedNode.oui}</div>
                        )}
                    </div>
                  </div>
                )}

                <div className="rounded border border-white/5 bg-white/5 p-4 space-y-3">
                  <div className="flex justify-between text-[10px] font-bold text-slate-500 uppercase">
                      <span>Address</span>
                      <span className="text-white font-mono">{selectedNode.ip}</span>
                  </div>
                  {selectedNode.signalStrength && (
                    <div className="flex flex-col gap-1">
                        <div className="flex justify-between text-[10px] font-bold text-slate-500 uppercase">
                          <span>Wireless Link Quality</span>
                          <span className="text-cyan-400 font-mono">{selectedNode.signalStrength}%</span>
                        </div>
                        <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
                          <div className="h-full bg-cyan-500 shadow-[0_0_5px_rgba(6,182,212,0.8)]" style={{ width: `${selectedNode.signalStrength}%` }} />
                        </div>
                    </div>
                  )}
                </div>

                {selectedNode.ssids && (
                  <div>
                    <h3 className="mb-2 text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                      <Radio size={10} /> Active Broadcasts
                    </h3>
                    <div className="space-y-1">
                      {selectedNode.ssids.map(ssid => (
                        <div key={ssid} className="group flex items-center justify-between rounded border border-white/5 bg-white/5 px-3 py-2 text-[10px]">
                            <span className="text-cyan-400 font-bold">{ssid}</span>
                            <span className="text-slate-500 uppercase">{connections.filter(c => c.ssid === ssid).length} Clients</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-4 border-t border-white/10">
                  <button className="w-full flex items-center justify-center gap-2 rounded bg-red-500/10 border border-red-500/30 py-2.5 text-[10px] font-black text-red-400 hover:bg-red-500/20 uppercase tracking-widest transition-all">
                      <Lock size={12} /> Isolate Hardware
                  </button>
                </div>
            </div>
          )}

          {activeTab === 'connections' && (
             <div className="space-y-2 animate-in fade-in slide-in-from-bottom-2 duration-300">
                {nodeConnections.length === 0 ? (
                    <div className="p-4 rounded border border-dashed border-white/10 text-center">
                      <span className="text-[10px] text-slate-600 font-bold uppercase">No Active Connections</span>
                    </div>
                ) : (
                  nodeConnections.map(c => {
                    const otherNode = nodes.find(n => n.id === (c.from === selectedNode.id ? c.to : c.from));
                    const isWireless = c.type === 'wireless';
                    return (
                      <div 
                        key={c.id}
                        onMouseEnter={() => setHoveredConnection(c.id)}
                        onMouseLeave={() => setHoveredConnection(null)}
                        className={`group rounded bg-white/5 border p-3 transition-colors cursor-pointer ${hoveredConnection === c.id ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-white/5 hover:border-cyan-500/30'}`}
                      >
                         <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                               <div className={`h-2 w-2 rounded-full ${otherNode?.status === 'online' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                               <div>
                                  <div className="text-xs text-white font-bold">{otherNode?.label}</div>
                                  <div className="text-[9px] text-slate-500 font-mono">{otherNode?.ip}</div>
                               </div>
                            </div>
                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase tracking-wider ${isWireless ? 'bg-cyan-500/10 text-cyan-400' : 'bg-indigo-500/10 text-indigo-400'}`}>
                              {c.type}
                            </span>
                         </div>
                         <div className="mt-2 pl-5 flex items-center gap-4 text-[9px] text-slate-400">
                             <div className="flex items-center gap-1">
                                {isWireless ? <Wifi size={10} /> : <Zap size={10} />}
                                <span>{isWireless ? (c.ssid || 'Ad-Hoc') : 'Ethernet'}</span>
                             </div>
                             {c.speed && <div className="font-mono text-slate-500">{c.speed}</div>}
                         </div>
                      </div>
                    );
                  })
                )}
             </div>
          )}

          {activeTab === 'traffic' && (
             <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                 {nodeConnections.length === 0 ? (
                    <div className="p-4 rounded border border-dashed border-white/10 text-center">
                      <span className="text-[10px] text-slate-600 font-bold uppercase">No Active Connections</span>
                    </div>
                 ) : (
                    nodeConnections.map(c => {
                      const otherNode = nodes.find(n => n.id === (c.from === selectedNode.id ? c.to : c.from));
                      const isWireless = c.type === 'wireless';
                      const graphColor = isWireless ? '#06b6d4' : '#6366f1';
                      return (
                        <div 
                          key={c.id} 
                          onMouseEnter={() => setHoveredConnection(c.id)}
                          onMouseLeave={() => setHoveredConnection(null)}
                          className={`rounded bg-white/5 border p-3 ${hoveredConnection === c.id ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-white/5'}`}
                        >
                           <div className="flex items-center justify-between mb-3">
                              <div className="text-[10px] font-bold text-slate-400">
                                <span className="text-slate-600 mr-1">LINK:</span> {otherNode?.label}
                              </div>
                              <span className="text-[9px] font-mono text-cyan-400 animate-pulse">LIVE</span>
                           </div>
                           <TrafficGraph value={c.traffic} color={graphColor} />
                        </div>
                      );
                    })
                 )}
             </div>
          )}
       </div>
    </div>
  );
};
