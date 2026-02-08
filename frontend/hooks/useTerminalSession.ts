import { useState, useCallback, useEffect } from 'react';
import { ShellInfo, TerminalSessionState } from '../types';

const API_ORIGIN = (import.meta.env.VITE_NETSEC_API_ORIGIN as string | undefined)?.replace(/\/$/, '') || 'http://127.0.0.1:8420';
const API_BASE = `${API_ORIGIN}/api`;

interface TerminalSessionInfo {
  session_id: string;
  shell: string;
  created_at: string;
  cols: number;
  rows: number;
}

interface AvailableShellsResponse {
  shells: ShellInfo[];
}

// Singleton cache for available shells
let cachedShells: ShellInfo[] | null = null;
let shellsFetchPromise: Promise<ShellInfo[]> | null = null;

export const useTerminalSession = () => {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [state, setState] = useState<TerminalSessionState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [shell, setShell] = useState<ShellInfo | null>(null);

  const createSession = useCallback(async (shellPath?: string): Promise<string | null> => {
    setState('creating');
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/terminal`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ shell: shellPath }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: 'Failed to create terminal session' }));
        throw new Error(err.detail || 'Failed to create terminal session');
      }

      const data: TerminalSessionInfo = await response.json();
      setSessionId(data.session_id);
      setState('connected');
      return data.session_id;
    } catch (e: unknown) {
      const errorMessage = e instanceof Error ? e.message : 'Failed to create terminal session';
      setError(errorMessage);
      setState('error');
      return null;
    }
  }, []);

  const closeSession = useCallback(async () => {
    if (!sessionId) return;

    try {
      await fetch(`${API_BASE}/terminal/${sessionId}`, {
        method: 'DELETE',
      });
    } catch (e) {
      console.warn('Failed to close terminal session:', e);
    }

    setSessionId(null);
    setState('idle');
    setShell(null);
  }, [sessionId]);

  const resizeSession = useCallback(async (cols: number, rows: number) => {
    if (!sessionId) return;

    try {
      await fetch(`${API_BASE}/terminal/${sessionId}/resize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ cols, rows }),
      });
    } catch (e) {
      console.warn('Failed to resize terminal session:', e);
    }
  }, [sessionId]);

  const setSessionState = useCallback((newState: TerminalSessionState) => {
    setState(newState);
  }, []);

  const setSessionShell = useCallback((newShell: ShellInfo | null) => {
    setShell(newShell);
  }, []);

  return {
    sessionId,
    state,
    error,
    shell,
    createSession,
    closeSession,
    resizeSession,
    setSessionState,
    setSessionShell,
  };
};

/**
 * Hook to fetch available shells (with caching)
 */
export const useAvailableShells = () => {
  const [shells, setShells] = useState<ShellInfo[]>(cachedShells || []);
  const [loading, setLoading] = useState(!cachedShells);
  const [error, setError] = useState<string | null>(null);

  const fetchShells = useCallback(async (force = false): Promise<ShellInfo[]> => {
    // Return cached if available and not forcing refresh
    if (cachedShells && !force) {
      return cachedShells;
    }

    // Return existing promise if fetch is in progress
    if (shellsFetchPromise && !force) {
      return shellsFetchPromise;
    }

    setLoading(true);
    setError(null);

    shellsFetchPromise = fetch(`${API_BASE}/terminal/shells`)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error('Failed to fetch available shells');
        }
        const data: AvailableShellsResponse = await response.json();
        cachedShells = data.shells;
        setShells(data.shells);
        return data.shells;
      })
      .catch((e) => {
        const errorMessage = e instanceof Error ? e.message : 'Failed to fetch shells';
        setError(errorMessage);
        // Return default shells if fetch fails
        const defaultShells: ShellInfo[] = [
          { id: 'default', name: 'Default Shell', path: '' }
        ];
        setShells(defaultShells);
        return defaultShells;
      })
      .finally(() => {
        setLoading(false);
        shellsFetchPromise = null;
      });

    return shellsFetchPromise;
  }, []);

  // Fetch on mount if not cached
  useEffect(() => {
    if (!cachedShells) {
      fetchShells();
    }
  }, [fetchShells]);

  return {
    shells,
    loading,
    error,
    fetchShells,
  };
};
