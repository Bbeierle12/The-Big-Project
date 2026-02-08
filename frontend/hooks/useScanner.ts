
import React, { useState, useEffect } from 'react';
import { Node } from '../types';
import { inferSubnetTarget } from '../utils/networkUtils';
import { NetWatchApi } from '../services/api';

export const useScanner = (
  nodes: Node[], 
  setSelectedIds: (ids: string[]) => void
) => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanError, setScanError] = useState<string | null>(null);

  useEffect(() => {
    // Listen for real backend scan events
    const handleScanProgress = (data: { scan_id: string, progress: number }) => {
      setScanError(null);
      setScanProgress(data.progress);
    };

    const handleScanComplete = (data: { scan_id: string, results: any }) => {
      setIsScanning(false);
      setScanError(null);
      setScanProgress(100);
      setTimeout(() => setScanProgress(0), 2000);
      // Backend should trigger device.discovered events which useNetwork handles
    };

    NetWatchApi.on('scan.progress', handleScanProgress);
    NetWatchApi.on('scan.completed', handleScanComplete);

    return () => {
      NetWatchApi.off('scan.progress', handleScanProgress);
      NetWatchApi.off('scan.completed', handleScanComplete);
    };
  }, []);

  const scanNetwork = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanError(null);
    setScanProgress(0);
    setSelectedIds([]);

    try {
      // Launch real scan with proper payload structure
      await NetWatchApi.launchScan({
        scan_type: 'network',
        tool: 'nmap',
        target: inferSubnetTarget(nodes)
      });
    } catch (e: any) {
      const message = e?.message || String(e);
      setIsScanning(false);
      setScanProgress(0);
      setScanError(`Scan failed: ${message}`);
    }
  };

  return { isScanning, scanProgress, scanError, scanNetwork };
};
