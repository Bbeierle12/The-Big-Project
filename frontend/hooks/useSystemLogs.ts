import { useState, useEffect, useCallback } from 'react';
import { NetWatchApi } from '../services/api';

const MAX_LOGS = 100;

const formatTimestamp = () => {
  const now = new Date();
  return now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

export const useSystemLogs = () => {
  const [logs, setLogs] = useState<string[]>([]);

  const addLog = useCallback((message: string, level: 'INFO' | 'WARN' | 'ERROR' = 'INFO') => {
    const timestamp = formatTimestamp();
    const formattedLog = `[${timestamp}] [${level}] ${message}`;

    setLogs(prev => {
      const newLogs = [...prev, formattedLog];
      // Keep only the last MAX_LOGS entries
      return newLogs.length > MAX_LOGS ? newLogs.slice(-MAX_LOGS) : newLogs;
    });
  }, []);

  useEffect(() => {
    // System startup/shutdown
    const handleStartup = () => {
      addLog('NetWatch Agent connected', 'INFO');
    };

    const handleShutdown = () => {
      addLog('NetWatch Agent disconnected - attempting reconnect...', 'WARN');
    };

    // Device events
    const handleDeviceDiscovered = (evt: any) => {
      const identifier = evt.hostname || evt.ip || evt.device_id;
      addLog(`Device discovered: ${identifier}`, 'INFO');
    };

    const handleDeviceUpdated = (evt: any) => {
      const identifier = evt.hostname || evt.ip || evt.device_id;
      addLog(`Device updated: ${identifier}`, 'INFO');
    };

    const handleDeviceOffline = (evt: any) => {
      const deviceId = typeof evt === 'string' ? evt : evt.device_id;
      addLog(`Device went offline: ${deviceId}`, 'WARN');
    };

    // Scan events
    const handleScanStarted = (evt: any) => {
      addLog(`Scan started: ${evt.scan_type || 'network'} scan (${evt.id?.slice(0, 8) || 'unknown'})`, 'INFO');
    };

    const handleScanProgress = (evt: any) => {
      const progress = evt.progress ? `${evt.progress}%` : 'in progress';
      addLog(`Scan ${evt.id?.slice(0, 8) || ''}: ${progress}`, 'INFO');
    };

    const handleScanCompleted = (evt: any) => {
      const devices = evt.devices_found || 0;
      addLog(`Scan completed: ${devices} device(s) found`, 'INFO');
    };

    const handleScanFailed = (evt: any) => {
      addLog(`Scan failed: ${evt.error || 'Unknown error'}`, 'ERROR');
    };

    // Alert events
    const handleAlertCreated = (evt: any) => {
      const severity = evt.severity?.toUpperCase() || 'UNKNOWN';
      const title = evt.title || 'New alert';
      addLog(`ALERT [${severity}]: ${title}`, severity === 'CRITICAL' ? 'ERROR' : 'WARN');
    };

    const handleAlertUpdated = (evt: any) => {
      addLog(`Alert ${evt.id?.slice(0, 8) || ''} status: ${evt.status}`, 'INFO');
    };

    // Tool events
    const handleToolStarted = (evt: any) => {
      addLog(`Tool started: ${evt.tool || 'unknown'} - ${evt.task || 'task'}`, 'INFO');
    };

    const handleToolCompleted = (evt: any) => {
      addLog(`Tool completed: ${evt.tool || 'unknown'}`, 'INFO');
    };

    const handleToolError = (evt: any) => {
      addLog(`Tool error: ${evt.tool || 'unknown'} - ${evt.error || 'failed'}`, 'ERROR');
    };

    // Register all event handlers
    NetWatchApi.on('system.startup', handleStartup);
    NetWatchApi.on('system.shutdown', handleShutdown);
    NetWatchApi.on('device.discovered', handleDeviceDiscovered);
    NetWatchApi.on('device.updated', handleDeviceUpdated);
    NetWatchApi.on('device.offline', handleDeviceOffline);
    NetWatchApi.on('scan.started', handleScanStarted);
    NetWatchApi.on('scan.progress', handleScanProgress);
    NetWatchApi.on('scan.completed', handleScanCompleted);
    NetWatchApi.on('scan.failed', handleScanFailed);
    NetWatchApi.on('alert.created', handleAlertCreated);
    NetWatchApi.on('alert.updated', handleAlertUpdated);
    NetWatchApi.on('tool.started', handleToolStarted);
    NetWatchApi.on('tool.completed', handleToolCompleted);
    NetWatchApi.on('tool.error', handleToolError);

    // Initial log
    addLog('System console initialized', 'INFO');

    // Cleanup
    return () => {
      NetWatchApi.off('system.startup', handleStartup);
      NetWatchApi.off('system.shutdown', handleShutdown);
      NetWatchApi.off('device.discovered', handleDeviceDiscovered);
      NetWatchApi.off('device.updated', handleDeviceUpdated);
      NetWatchApi.off('device.offline', handleDeviceOffline);
      NetWatchApi.off('scan.started', handleScanStarted);
      NetWatchApi.off('scan.progress', handleScanProgress);
      NetWatchApi.off('scan.completed', handleScanCompleted);
      NetWatchApi.off('scan.failed', handleScanFailed);
      NetWatchApi.off('alert.created', handleAlertCreated);
      NetWatchApi.off('alert.updated', handleAlertUpdated);
      NetWatchApi.off('tool.started', handleToolStarted);
      NetWatchApi.off('tool.completed', handleToolCompleted);
      NetWatchApi.off('tool.error', handleToolError);
    };
  }, [addLog]);

  const clearLogs = useCallback(() => {
    setLogs([]);
    addLog('Logs cleared', 'INFO');
  }, [addLog]);

  return { logs, addLog, clearLogs };
};
