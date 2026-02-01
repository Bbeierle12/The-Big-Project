import React, { useEffect, useState, useCallback } from 'react';
import { Terminal as TermIcon, ChevronDown, ChevronUp } from 'lucide-react';
import { XTerminal } from './XTerminal';
import { TerminalTabs } from './TerminalTabs';
import { useAvailableShells } from '../hooks/useTerminalSession';
import { ShellInfo, TerminalTab, TerminalSessionState } from '../types';

// Generate unique IDs for tabs
let tabIdCounter = 0;
const generateTabId = () => `tab-${++tabIdCounter}`;

export const ConsolePanel: React.FC = () => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [tabs, setTabs] = useState<TerminalTab[]>([]);
  const [activeTabId, setActiveTabId] = useState<string | null>(null);
  const [sessions, setSessions] = useState<Map<string, string | null>>(new Map());

  const { shells, loading: shellsLoading } = useAvailableShells();

  // Create initial tab once shells are loaded
  useEffect(() => {
    if (shells.length > 0 && tabs.length === 0) {
      const defaultShell = shells[0];
      const newTabId = generateTabId();
      const newTab: TerminalTab = {
        id: newTabId,
        sessionId: null,
        shell: defaultShell,
        state: 'idle',
        title: defaultShell.name,
      };
      setTabs([newTab]);
      setActiveTabId(newTabId);
    }
  }, [shells, tabs.length]);

  const handleNewTab = useCallback((shell: ShellInfo) => {
    const newTabId = generateTabId();
    const newTab: TerminalTab = {
      id: newTabId,
      sessionId: null,
      shell,
      state: 'idle',
      title: shell.name,
    };
    setTabs(prev => [...prev, newTab]);
    setActiveTabId(newTabId);
  }, []);

  const handleTabClose = useCallback((tabId: string) => {
    setTabs(prev => {
      const newTabs = prev.filter(t => t.id !== tabId);

      // If closing active tab, switch to another tab
      if (activeTabId === tabId && newTabs.length > 0) {
        const closedIndex = prev.findIndex(t => t.id === tabId);
        const newActiveIndex = Math.min(closedIndex, newTabs.length - 1);
        setActiveTabId(newTabs[newActiveIndex].id);
      } else if (newTabs.length === 0) {
        setActiveTabId(null);
      }

      return newTabs;
    });

    // Clean up session mapping
    setSessions(prev => {
      const newSessions = new Map(prev);
      newSessions.delete(tabId);
      return newSessions;
    });
  }, [activeTabId]);

  const handleTabSelect = useCallback((tabId: string) => {
    setActiveTabId(tabId);
  }, []);

  const handleSessionCreated = useCallback((tabId: string, sessionId: string) => {
    setSessions(prev => new Map(prev).set(tabId, sessionId));
    setTabs(prev => prev.map(t =>
      t.id === tabId ? { ...t, sessionId, state: 'connected' as TerminalSessionState } : t
    ));
  }, []);

  const handleSessionStateChange = useCallback((tabId: string, state: TerminalSessionState) => {
    setTabs(prev => prev.map(t =>
      t.id === tabId ? { ...t, state } : t
    ));
  }, []);

  return (
    <div className="z-40 flex flex-col border-t border-white/10 bg-black/95 backdrop-blur-md">
      {/* Header bar with collapse toggle */}
      <div
        className="flex items-center justify-between px-4 py-1.5 bg-slate-900/80 border-b border-white/5 cursor-pointer hover:bg-slate-800/80 transition-colors"
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <TermIcon size={12} />
            <span className="uppercase tracking-wider font-semibold">Terminal</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <span>{tabs.length} {tabs.length === 1 ? 'session' : 'sessions'}</span>
          </div>
        </div>
        <button
          type="button"
          className="text-slate-400 hover:text-white transition-colors"
          onClick={(e) => {
            e.stopPropagation();
            setIsCollapsed(!isCollapsed);
          }}
        >
          {isCollapsed ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </button>
      </div>

      {/* Terminal panels */}
      {!isCollapsed && (
        <div className="flex flex-col h-64 overflow-hidden">
          {/* Tab bar */}
          <TerminalTabs
            tabs={tabs}
            activeTabId={activeTabId}
            shells={shells}
            onTabSelect={handleTabSelect}
            onTabClose={handleTabClose}
            onNewTab={handleNewTab}
          />

          {/* Terminal area */}
          <div className="flex-1 overflow-hidden relative">
            {tabs.length === 0 ? (
              <div className="flex items-center justify-center h-full text-slate-500 text-sm">
                {shellsLoading ? (
                  'Loading shells...'
                ) : (
                  <button
                    type="button"
                    onClick={() => shells.length > 0 && handleNewTab(shells[0])}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    <TermIcon size={16} />
                    Create a terminal
                  </button>
                )}
              </div>
            ) : (
              tabs.map((tab) => (
                <div
                  key={tab.id}
                  className={`absolute inset-0 ${tab.id === activeTabId ? 'visible' : 'invisible'}`}
                >
                  <XTerminal
                    tabId={tab.id}
                    shell={tab.shell}
                    sessionId={sessions.get(tab.id) || null}
                    onSessionCreated={(sessionId) => handleSessionCreated(tab.id, sessionId)}
                    onStateChange={(state) => handleSessionStateChange(tab.id, state)}
                  />
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};
