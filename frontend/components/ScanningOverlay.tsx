import React from 'react';

interface ScanningOverlayProps {
  isScanning: boolean;
  scanProgress: number;
}

export const ScanningOverlay: React.FC<ScanningOverlayProps> = ({ isScanning, scanProgress }) => {
  if (!isScanning) return null;

  return (
    <div className="pointer-events-none absolute inset-0 z-40 flex items-center justify-center">
       {/* Radar Circle */}
       <div className="absolute h-[150vh] w-[150vh] animate-[spin_4s_linear_infinite] rounded-full bg-[conic-gradient(from_0deg,transparent_0_340deg,rgba(6,182,212,0.1)_360deg)] opacity-30" />
       <div className="absolute h-[60vh] w-[60vh] rounded-full border border-cyan-500/10 opacity-50" />
       <div className="absolute h-[30vh] w-[30vh] rounded-full border border-cyan-500/20 opacity-50" />
       
       {/* Progress HUD */}
       <div className="absolute bottom-12 flex flex-col items-center gap-2">
          <div className="flex items-center gap-4 rounded-full border border-cyan-500/30 bg-black/80 px-6 py-3 shadow-[0_0_30px_rgba(6,182,212,0.2)] backdrop-blur-md">
             <div className="relative h-3 w-3">
                <div className="absolute inset-0 animate-ping rounded-full bg-cyan-400 opacity-75"></div>
                <div className="relative h-3 w-3 rounded-full bg-cyan-500"></div>
             </div>
             <div className="flex flex-col min-w-[12rem]">
                <span className="text-[10px] font-black uppercase tracking-widest text-cyan-400">
                  Signal Trace In Progress
                </span>
                <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-slate-800">
                   <div 
                     className="h-full bg-cyan-400 transition-all duration-300 ease-out" 
                     style={{ width: `${scanProgress}%` }}
                   />
                </div>
             </div>
             <span className="font-mono text-xs font-bold text-white">{scanProgress}%</span>
          </div>
          <div className="font-mono text-[9px] text-cyan-500/70 animate-pulse">
             DECODING PACKET HEADERS...
          </div>
       </div>
    </div>
  );
};
