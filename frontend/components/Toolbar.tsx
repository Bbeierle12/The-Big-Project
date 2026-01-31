import React from 'react';
import {
  MousePointer, Share2, Router, Wifi, Cpu, Smartphone,
  Laptop, FolderPlus, Trash2, ShieldAlert, Search, Skull,
  Scan, Monitor, Server, Bug
} from 'lucide-react';
import { ToolButton } from './ToolButton';
import { NodeType } from '../types';

interface ToolbarProps {
  mode: 'select' | 'connect';
  setMode: (mode: 'select' | 'connect') => void;
  onAddNode: (type: NodeType) => void;
  onGroup: () => void;
  onDelete: () => void;
  onPentest: (tool: string) => void;
}

export const Toolbar: React.FC<ToolbarProps> = ({ mode, setMode, onAddNode, onGroup, onDelete, onPentest }) => {
  return (
    <div className="z-30 flex w-20 flex-col items-center gap-2 border-r border-white/10 bg-black/60 py-3 px-1 backdrop-blur-sm">
      <ToolButton active={mode === 'select'} icon={MousePointer} label="Select" onClick={() => setMode('select')} />
      <ToolButton active={mode === 'connect'} icon={Share2} label="Link" onClick={() => setMode('connect')} />

      <div className="my-1 h-px w-12 bg-white/10" />
      <div className="text-[7px] font-black text-slate-500 uppercase tracking-widest">Add</div>
      <ToolButton icon={Router} label="Router" onClick={() => onAddNode('router')} />
      <ToolButton icon={Wifi} label="AP" onClick={() => onAddNode('extender')} />
      <ToolButton icon={Cpu} label="IoT" onClick={() => onAddNode('iot')} />
      <ToolButton icon={Smartphone} label="Mobile" onClick={() => onAddNode('mobile')} />
      <ToolButton icon={Laptop} label="Laptop" onClick={() => onAddNode('workstation')} />

      <div className="my-1 h-px w-12 bg-white/10" />
      <div className="text-[7px] font-black text-emerald-700 uppercase tracking-widest">Nmap</div>

      <button
        onClick={() => onPentest('nmap:quick_scan')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-emerald-500/50 hover:text-emerald-400 hover:bg-emerald-900/20 transition-all duration-200"
        title="Ping scan - fast host discovery"
      >
        <Search size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">Quick</span>
      </button>

      <button
        onClick={() => onPentest('nmap:port_scan')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-emerald-500/50 hover:text-emerald-400 hover:bg-emerald-900/20 transition-all duration-200"
        title="TCP SYN scan on common ports"
      >
        <Scan size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">Ports</span>
      </button>

      <button
        onClick={() => onPentest('nmap:service_detect')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-emerald-500/50 hover:text-emerald-400 hover:bg-emerald-900/20 transition-all duration-200"
        title="Service and version detection"
      >
        <Server size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">Service</span>
      </button>

      <button
        onClick={() => onPentest('nmap:os_detect')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-emerald-500/50 hover:text-emerald-400 hover:bg-emerald-900/20 transition-all duration-200"
        title="Operating system fingerprinting"
      >
        <Monitor size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">OS</span>
      </button>

      <button
        onClick={() => onPentest('nmap:vuln_scan')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-amber-500/50 hover:text-amber-400 hover:bg-amber-900/20 transition-all duration-200"
        title="Vulnerability scanning scripts"
      >
        <Bug size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">Vuln</span>
      </button>

      <button
        onClick={() => onPentest('nmap:full_scan')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-cyan-500/50 hover:text-cyan-400 hover:bg-cyan-900/20 transition-all duration-200"
        title="Full scan: services + OS + scripts"
      >
        <Scan size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">Full</span>
      </button>

      <div className="my-1 h-px w-12 bg-white/10" />
      <div className="text-[7px] font-black text-rose-700 uppercase tracking-widest">Attack</div>

      <button
        onClick={() => onPentest('hydra')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-amber-500/50 hover:text-amber-400 hover:bg-amber-900/20 transition-all duration-200"
        title="Brute force password attack"
      >
        <ShieldAlert size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">Hydra</span>
      </button>

      <button
        onClick={() => onPentest('metasploit')}
        className="flex flex-col items-center justify-center gap-1 w-full py-2 px-1 rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-rose-500/50 hover:text-rose-400 hover:bg-rose-900/20 transition-all duration-200"
        title="Metasploit exploitation framework"
      >
        <Skull size={16} />
        <span className="text-[8px] font-bold uppercase tracking-wide">Msf</span>
      </button>

      <div className="mt-auto pt-3 border-t border-white/10 w-full flex flex-col items-center gap-2">
         <ToolButton icon={FolderPlus} label="Group" onClick={onGroup} />
         <ToolButton icon={Trash2} label="Delete" onClick={onDelete} />
      </div>
    </div>
  );
};