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
    className={`group relative flex flex-col items-center justify-center gap-1 rounded-sm border transition-all duration-200 z-30 w-full py-2 px-1
      ${active
        ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.3)]'
        : 'border-white/10 bg-black/40 text-slate-400 hover:border-cyan-500/50 hover:text-cyan-400'
      }`}
    title={label}
  >
    <Icon size={16} />
    <span className="text-[8px] font-bold uppercase tracking-wide truncate w-full text-center">
      {label}
    </span>
  </button>
);