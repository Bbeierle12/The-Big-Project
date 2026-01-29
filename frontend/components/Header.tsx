
import React from 'react';
import { Network, Activity, Search, FolderOpen, Save, ShieldAlert } from 'lucide-react';

interface HeaderProps {
  isScanning: boolean;
  onScan: () => void;
  onSave: () => void;
  onLoad: () => void;
  onShowVulnReport: () => void;
}

export const Header: React.FC<HeaderProps> = ({ isScanning, onScan, onSave, onLoad, onShowVulnReport }) => {
  return (
    <header className="z-30 flex h-14 items-center justify-between border-b border-white/10 bg-black/80 px-6 backdrop-blur-md">
      <div className="flex items-center gap-4">
        <div className="flex h-8 w-8 items-center justify-center rounded bg-cyan-500/10 text-cyan-400">
          <Network size={20} />
        </div>
        <div>
          <h1 className="text-lg font-bold tracking-tight text-white uppercase">Archangel Deep-Scanner</h1>
          <div className="flex items-center gap-2 text-[10px] text-slate-500 font-bold uppercase tracking-widest">
            <span className={`h-1.5 w-1.5 rounded-full ${isScanning ? 'bg-amber-500 animate-pulse' : 'bg-emerald-500'}`}></span>
            {isScanning ? 'Decoding OUI Signatures...' : 'System Primed'}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
         <button 
           onClick={onShowVulnReport}
           className="flex items-center gap-2 rounded bg-red-500/10 border border-red-500/30 px-4 py-1.5 text-xs font-bold text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors mr-4"
         >
           <ShieldAlert size={14} />
           VULN REPORT
         </button>

         <button 
           onClick={onScan}
           disabled={isScanning}
           className={`flex items-center gap-2 rounded px-4 py-1.5 text-xs font-bold transition-all ${isScanning ? 'bg-slate-800 text-slate-500' : 'bg-cyan-600 text-white hover:bg-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.4)]'}`}
         >
           {isScanning ? <Activity className="animate-spin" size={14} /> : <Search size={14} />}
           IDENTIFY VENDORS
         </button>
         
         <button 
           onClick={onLoad}
           className="flex items-center gap-2 rounded bg-white/5 border border-white/10 px-4 py-1.5 text-xs font-bold text-white hover:bg-white/10"
         >
           <FolderOpen size={14} /> LOAD
         </button>

         <button 
           onClick={onSave}
           className="flex items-center gap-2 rounded bg-white/5 border border-white/10 px-4 py-1.5 text-xs font-bold text-white hover:bg-white/10"
         >
           <Save size={14} /> SAVE
         </button>
      </div>
    </header>
  );
};
