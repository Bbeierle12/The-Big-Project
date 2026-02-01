import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TermIcon, Plus, X, ChevronDown } from 'lucide-react';
import { ShellInfo, TerminalTab, TerminalSessionState } from '../types';

interface TerminalTabsProps {
  tabs: TerminalTab[];
  activeTabId: string | null;
  shells: ShellInfo[];
  onTabSelect: (tabId: string) => void;
  onTabClose: (tabId: string) => void;
  onNewTab: (shell: ShellInfo) => void;
}

export const TerminalTabs: React.FC<TerminalTabsProps> = ({
  tabs,
  activeTabId,
  shells,
  onTabSelect,
  onTabClose,
  onNewTab,
}) => {
  const [showShellMenu, setShowShellMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        menuRef.current &&
        !menuRef.current.contains(e.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(e.target as Node)
      ) {
        setShowShellMenu(false);
      }
    };

    if (showShellMenu) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showShellMenu]);

  const getStatusColor = (state: TerminalSessionState): string => {
    switch (state) {
      case 'connected':
        return 'bg-emerald-500';
      case 'creating':
        return 'bg-yellow-500 animate-pulse';
      case 'error':
      case 'disconnected':
        return 'bg-red-500';
      default:
        return 'bg-slate-500';
    }
  };

  const getShellIcon = (shell: ShellInfo | null): string => {
    if (!shell) return 'λ';
    const id = shell.id.toLowerCase();
    if (id.includes('pwsh') || id.includes('powershell')) return 'PS';
    if (id.includes('cmd')) return '>';
    if (id.includes('bash') || id.includes('git-bash')) return '$';
    if (id.includes('wsl')) return 'λ';
    if (id.includes('zsh')) return 'Z';
    if (id.includes('fish')) return '><>';
    return 'λ';
  };

  return (
    <div className="flex items-center gap-1 px-2 py-1 bg-slate-900/50 border-b border-white/5 overflow-x-auto">
      {/* Tabs */}
      {tabs.map((tab) => (
        <div
          key={tab.id}
          className={`
            flex items-center gap-2 px-3 py-1.5 rounded-t text-xs cursor-pointer
            transition-colors group min-w-0
            ${activeTabId === tab.id
              ? 'bg-slate-800 text-white border-t border-x border-white/10'
              : 'bg-transparent text-slate-400 hover:bg-slate-800/50 hover:text-slate-300'
            }
          `}
          onClick={() => onTabSelect(tab.id)}
        >
          {/* Status indicator */}
          <div className={`w-2 h-2 rounded-full flex-shrink-0 ${getStatusColor(tab.state)}`} />

          {/* Shell icon */}
          <span className="font-mono text-[10px] text-cyan-400 flex-shrink-0">
            {getShellIcon(tab.shell)}
          </span>

          {/* Title */}
          <span className="truncate max-w-[100px]">
            {tab.title || tab.shell?.name || 'Terminal'}
          </span>

          {/* Close button */}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onTabClose(tab.id);
            }}
            className={`
              p-0.5 rounded hover:bg-red-500/20 hover:text-red-400
              transition-colors flex-shrink-0
              ${activeTabId === tab.id ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}
            `}
            title="Close terminal"
          >
            <X size={12} />
          </button>
        </div>
      ))}

      {/* Add new terminal button */}
      <div className="relative">
        <button
          ref={buttonRef}
          type="button"
          onClick={() => setShowShellMenu(!showShellMenu)}
          className="flex items-center gap-1 px-2 py-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700/50 transition-colors text-xs"
          title="New terminal"
        >
          <Plus size={14} />
          <ChevronDown size={10} className={`transition-transform ${showShellMenu ? 'rotate-180' : ''}`} />
        </button>

        {/* Shell selection dropdown */}
        {showShellMenu && (
          <div
            ref={menuRef}
            className="absolute left-0 top-full mt-1 z-50 bg-slate-800 border border-white/10 rounded-lg shadow-xl py-1 min-w-[180px]"
          >
            <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
              Select Shell
            </div>
            {shells.length === 0 ? (
              <div className="px-3 py-2 text-xs text-slate-500">
                No shells available
              </div>
            ) : (
              shells.map((shell) => (
                <button
                  key={shell.id}
                  type="button"
                  onClick={() => {
                    onNewTab(shell);
                    setShowShellMenu(false);
                  }}
                  className="w-full flex items-center gap-3 px-3 py-2 text-xs text-left text-slate-300 hover:bg-cyan-500/10 hover:text-white transition-colors"
                >
                  <span className="font-mono text-cyan-400 w-6">
                    {getShellIcon(shell)}
                  </span>
                  <div className="flex flex-col">
                    <span>{shell.name}</span>
                    <span className="text-[10px] text-slate-500 truncate max-w-[140px]">
                      {shell.path}
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};
