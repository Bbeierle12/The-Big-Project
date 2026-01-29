import React from 'react';

interface ToolButtonProps {
  active?: boolean;
  icon: React.ElementType;
  onClick: () => void;
  label: string;
}

export const ToolButton: React.FC<ToolButtonProps> = ({ active, icon: Icon, onClick, label }) => (
  <button
    onClick={onClick}
    className={`group relative flex h-10 w-10 items-center justify-center rounded-sm border transition-all duration-200 z-30
      ${active 
        ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.3)]' 
        : 'border-white/10 bg-black/40 text-slate-400 hover:border-cyan-500/50 hover:text-cyan-400'
      }`}
    title={label}
  >
    <Icon size={18} />
    <span className="pointer-events-none absolute left-full ml-2 hidden whitespace-nowrap rounded bg-slate-800 px-2 py-1 text-xs text-white opacity-0 transition-opacity group-hover:block group-hover:opacity-100">
      {label}
    </span>
  </button>
);