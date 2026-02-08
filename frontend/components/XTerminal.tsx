import React, { useEffect, useRef, useCallback, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { ShellInfo, TerminalSessionState } from '../types';
import { RefreshCw } from 'lucide-react';

const API_ORIGIN = (import.meta.env.VITE_NETSEC_API_ORIGIN as string | undefined)?.replace(/\/$/, '') || 'http://127.0.0.1:8420';
const API_BASE = `${API_ORIGIN}/api`;
const WS_BASE = (import.meta.env.VITE_NETSEC_WS_URL as string | undefined)?.replace(/\/ws$/, '') || API_ORIGIN.replace(/^http/, 'ws');
const MAX_RECONNECT_ATTEMPTS = 3;
const RECONNECT_DELAY_MS = 2000;

interface XTerminalProps {
  tabId: string;
  shell: ShellInfo | null;
  sessionId: string | null;
  onSessionCreated: (sessionId: string) => void;
  onStateChange: (state: TerminalSessionState) => void;
}

export const XTerminal: React.FC<XTerminalProps> = ({
  tabId,
  shell,
  sessionId,
  onSessionCreated,
  onStateChange,
}) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const isCreatingSessionRef = useRef(false);

  const [connectionFailed, setConnectionFailed] = useState(false);

  // Create a new terminal session
  const createSession = useCallback(async () => {
    if (isCreatingSessionRef.current) return null;
    isCreatingSessionRef.current = true;

    onStateChange('creating');

    try {
      const response = await fetch(`${API_BASE}/terminal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ shell: shell?.path || null }),
      });

      if (!response.ok) {
        throw new Error('Failed to create session');
      }

      const data = await response.json();
      onSessionCreated(data.session_id);
      return data.session_id;
    } catch (e) {
      onStateChange('error');
      if (xtermRef.current) {
        xtermRef.current.writeln('\x1b[31mFailed to create terminal session.\x1b[0m');
      }
      return null;
    } finally {
      isCreatingSessionRef.current = false;
    }
  }, [shell, onSessionCreated, onStateChange]);

  // Initialize xterm.js terminal
  useEffect(() => {
    if (!terminalRef.current || xtermRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      cursorStyle: 'block',
      fontSize: 13,
      fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", Consolas, monospace',
      theme: {
        background: '#0a0a0a',
        foreground: '#e2e8f0',
        cursor: '#22d3ee',
        cursorAccent: '#0a0a0a',
        selectionBackground: '#334155',
        selectionForeground: '#e2e8f0',
        black: '#1e293b',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#eab308',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#22d3ee',
        white: '#e2e8f0',
        brightBlack: '#475569',
        brightRed: '#f87171',
        brightGreen: '#4ade80',
        brightYellow: '#facc15',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#67e8f9',
        brightWhite: '#f8fafc',
      },
      allowProposedApi: true,
      scrollback: 5000,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    // Welcome message
    term.writeln('\x1b[36m╔══════════════════════════════════════╗\x1b[0m');
    term.writeln('\x1b[36m║\x1b[0m   \x1b[1;32mNetWatch Terminal\x1b[0m                 \x1b[36m║\x1b[0m');
    term.writeln('\x1b[36m╚══════════════════════════════════════╝\x1b[0m');
    term.writeln('');

    if (shell) {
      term.writeln(`\x1b[90mShell: ${shell.name}\x1b[0m`);
      term.writeln('');
    }

    // Create session if we don't have one
    if (!sessionId) {
      term.writeln('\x1b[33mConnecting to terminal server...\x1b[0m');
      createSession();
    }

    return () => {
      term.dispose();
      xtermRef.current = null;
      fitAddonRef.current = null;
    };
  }, [tabId]); // Only reinitialize on tabId change

  // Handle resize
  useEffect(() => {
    const handleResize = () => {
      if (fitAddonRef.current && xtermRef.current) {
        fitAddonRef.current.fit();

        // Send resize to backend
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          const { cols, rows } = xtermRef.current;
          wsRef.current.send(JSON.stringify({
            type: 'resize',
            cols,
            rows
          }));
        }
      }
    };

    window.addEventListener('resize', handleResize);

    // Also observe the container for size changes
    const observer = new ResizeObserver(handleResize);
    if (terminalRef.current) {
      observer.observe(terminalRef.current);
    }

    return () => {
      window.removeEventListener('resize', handleResize);
      observer.disconnect();
    };
  }, []);

  // Manual reconnect handler
  const handleManualReconnect = useCallback(() => {
    setConnectionFailed(false);
    reconnectAttemptsRef.current = 0;

    if (xtermRef.current) {
      xtermRef.current.writeln('');
      xtermRef.current.writeln('\x1b[36mReconnecting...\x1b[0m');
    }

    createSession();
  }, [createSession]);

  // Connect to WebSocket when sessionId is available
  useEffect(() => {
    if (!sessionId || !xtermRef.current) return;

    const term = xtermRef.current;

    const connect = () => {
      const ws = new WebSocket(`${WS_BASE}/api/terminal/ws/${sessionId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttemptsRef.current = 0;
        setConnectionFailed(false);
        onStateChange('connected');
        term.writeln('\x1b[32mConnected to shell.\x1b[0m');
        term.writeln('');

        // Send initial resize
        if (fitAddonRef.current) {
          fitAddonRef.current.fit();
          const { cols, rows } = term;
          ws.send(JSON.stringify({ type: 'resize', cols, rows }));
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          switch (msg.type) {
            case 'output':
              // Decode base64 output and write to terminal
              const output = atob(msg.data);
              term.write(output);
              break;
            case 'exit':
              term.writeln('');
              term.writeln(`\x1b[33mProcess exited with code ${msg.code}\x1b[0m`);
              onStateChange('disconnected');
              break;
            case 'error':
              term.writeln(`\x1b[31mError: ${msg.message}\x1b[0m`);
              break;
            case 'pong':
              // Heartbeat response, ignore
              break;
          }
        } catch (e) {
          // If not JSON, write raw data
          term.write(event.data);
        }
      };

      ws.onclose = () => {
        term.writeln('');
        term.writeln('\x1b[33mDisconnected from shell.\x1b[0m');
        onStateChange('disconnected');

        // Check retry limit
        if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
          reconnectAttemptsRef.current++;
          const delay = RECONNECT_DELAY_MS * reconnectAttemptsRef.current;
          term.writeln(`\x1b[36mReconnecting in ${delay / 1000}s... (attempt ${reconnectAttemptsRef.current}/${MAX_RECONNECT_ATTEMPTS})\x1b[0m`);

          reconnectTimeoutRef.current = window.setTimeout(() => {
            connect();
          }, delay);
        } else {
          term.writeln('');
          term.writeln('\x1b[31mConnection failed after maximum retries.\x1b[0m');
          term.writeln('\x1b[90mClick the reconnect button to try again.\x1b[0m');
          setConnectionFailed(true);
          onStateChange('error');
        }
      };

      ws.onerror = () => {
        term.writeln('\x1b[31mConnection error.\x1b[0m');
      };
    };

    connect();

    // Handle user input
    const inputDisposable = term.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          type: 'input',
          data: btoa(data) // base64 encode input
        }));
      }
    });

    return () => {
      inputDisposable.dispose();
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [sessionId, onStateChange]);

  // Trigger fit when session becomes available
  useEffect(() => {
    if (sessionId && fitAddonRef.current) {
      setTimeout(() => fitAddonRef.current?.fit(), 100);
    }
  }, [sessionId]);

  return (
    <div className="h-full w-full relative">
      <div
        ref={terminalRef}
        className="h-full w-full bg-[#0a0a0a]"
        style={{ padding: '4px' }}
      />

      {/* Reconnect overlay */}
      {connectionFailed && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/80">
          <button
            type="button"
            onClick={handleManualReconnect}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors text-sm"
          >
            <RefreshCw size={16} />
            Reconnect
          </button>
        </div>
      )}
    </div>
  );
};
