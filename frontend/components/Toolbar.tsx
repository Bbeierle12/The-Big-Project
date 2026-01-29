import React from 'react';
import { 
  MousePointer, Share2, Router, Wifi, Cpu, Smartphone, 
  Laptop, FolderPlus, Trash2, ShieldAlert, Search, Skull
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
    <div className="z-30 flex w-16 flex-col items-center gap-3 border-r border-white/10 bg-black/60 py-4 backdrop-blur-sm">
      <ToolButton active={mode === 'select'} icon={MousePointer} label="Select" onClick={() => setMode('select')} />
      <ToolButton active={mode === 'connect'} icon={Share2} label="Manual Link" onClick={() => setMode('connect')} />
      
      <div className="my-2 h-px w-8 bg-white/10" />
      <div className="text-[8px] font-black text-slate-600 uppercase tracking-widest mb-1 rotate-90 w-4 h-4 flex items-center justify-center">ADD</div>
      <ToolButton icon={Router} label="Add Router" onClick={() => onAddNode('router')} />
      <ToolButton icon={Wifi} label="Add AP" onClick={() => onAddNode('extender')} />
      <ToolButton icon={Cpu} label="Add IoT" onClick={() => onAddNode('iot')} />
      <ToolButton icon={Smartphone} label="Add Mobile" onClick={() => onAddNode('mobile')} />
      <ToolButton icon={Laptop} label="Add Laptop" onClick={() => onAddNode('workstation')} />
      
      <div className="my-2 h-px w-8 bg-white/10" />
      <div className="text-[8px] font-black text-rose-900 uppercase tracking-widest mb-1 rotate-90 w-4 h-4 flex items-center justify-center">KALI</div>
      
      <button
        onClick={() => onPentest('nmap')}
        className="group relative flex h-10 w-10 items-center justify-center rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-emerald-500/50 hover:text-emerald-400 hover:bg-emerald-900/20 transition-all duration-200"
        title="Nmap Recon"
      >
        <Search size={18} />
        <span className="pointer-events-none absolute left-full ml-2 hidden whitespace-nowrap rounded bg-emerald-900 px-2 py-1 text-xs text-emerald-100 opacity-0 transition-opacity group-hover:block group-hover:opacity-100">
          Nmap Scan
        </span>
      </button>

      <button
        onClick={() => onPentest('hydra')}
        className="group relative flex h-10 w-10 items-center justify-center rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-amber-500/50 hover:text-amber-400 hover:bg-amber-900/20 transition-all duration-200"
        title="Hydra Brute Force"
      >
        <ShieldAlert size={18} />
        <span className="pointer-events-none absolute left-full ml-2 hidden whitespace-nowrap rounded bg-amber-900 px-2 py-1 text-xs text-amber-100 opacity-0 transition-opacity group-hover:block group-hover:opacity-100">
          Hydra Attack
        </span>
      </button>

      <button
        onClick={() => onPentest('metasploit')}
        className="group relative flex h-10 w-10 items-center justify-center rounded-sm border border-white/10 bg-black/40 text-slate-400 hover:border-rose-500/50 hover:text-rose-400 hover:bg-rose-900/20 transition-all duration-200"
        title="Metasploit Framework"
      >
        <Skull size={18} />
        <span className="pointer-events-none absolute left-full ml-2 hidden whitespace-nowrap rounded bg-rose-900 px-2 py-1 text-xs text-rose-100 opacity-0 transition-opacity group-hover:block group-hover:opacity-100">
          Metasploit
        </span>
      </button>

      <div className="mt-auto pt-4 border-t border-white/10 w-full flex flex-col items-center gap-3">
         <ToolButton icon={FolderPlus} label="Group Selected" onClick={onGroup} />
         <ToolButton icon={Trash2} label="Delete" onClick={onDelete} />
      </div>
    </div>
  );
};