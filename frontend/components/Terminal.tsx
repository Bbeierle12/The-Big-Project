import React, { useEffect, useRef } from 'react';
import { Terminal as TermIcon } from 'lucide-react';

export const Terminal = ({ logs }: { logs: string[] }) => {
  const endRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  if (logs.length === 0) return null;

  return (
    <div className="absolute bottom-6 right-6 z-40 w-96 rounded-md border border-white/10 bg-black/90 p-4 font-mono text-xs shadow-[0_0_30px_rgba(0,0,0,0.8)] backdrop-blur-md animate-in slide-in-from-bottom-4 duration-300">
      <div className="mb-2 flex items-center gap-2 border-b border-white/10 pb-2 text-slate-400">
        <TermIcon size={14} />
        <span className="font-bold uppercase tracking-widest">Kali Linux Console</span>
      </div>
      <div className="space-y-1 font-mono">
        {logs.map((log, i) => (
          <div key={i} className={`break-all ${log.startsWith('root@kali') ? 'text-cyan-400' : (log.includes('Error') ? 'text-red-500' : 'text-emerald-500 opacity-90')}`}>
            {log}
          </div>
        ))}
        <div ref={endRef} />
      </div>
      <div className="mt-2 h-3 w-2 bg-emerald-500 animate-pulse" />
    </div>
  );
};