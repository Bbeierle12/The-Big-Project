
import React, { useState, useEffect } from 'react';
import { Node, Connection } from '../types';
import { lookupOUI, randomIP, HARDWARE_POOL } from '../utils/networkUtils';
import { NetWatchApi } from '../services/api';

export const useScanner = (
  nodes: Node[], 
  setNodes: React.Dispatch<React.SetStateAction<Node[]>>,
  setConnections: React.Dispatch<React.SetStateAction<Connection[]>>,
  setSelectedIds: (ids: string[]) => void
) => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  useEffect(() => {
    // Listen for real backend scan events
    const handleScanProgress = (data: { scan_id: string, progress: number }) => {
      setScanProgress(data.progress);
    };

    const handleScanComplete = (data: { scan_id: string, results: any }) => {
      setIsScanning(false);
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
    setScanProgress(0);
    setSelectedIds([]);

    try {
      // Launch real scan with proper payload structure
      await NetWatchApi.launchScan({
        scan_type: 'network',
        tool: 'nmap',
        target: '192.168.1.0/24'
      });
    } catch (e) {
      // Fallback to simulation if API fails
      console.warn("Scan API failed, running simulation");
      simulateScan();
    }
  };

  const simulateScan = async () => {
    const delay = (ms: number) => new Promise(res => setTimeout(res, ms));
    const apList = nodes.filter(n => n.ssids && n.ssids.length > 0);
    const wirelessSpeeds = ['54 Mbps', '144 Mbps', '300 Mbps', '600 Mbps', '866 Mbps'];

    for (let i = 0; i < HARDWARE_POOL.length; i++) {
      await delay(600 + Math.random() * 800);
      const dev = HARDWARE_POOL[i];
      const id = `scan-${Date.now()}-${i}`;
      
      const hostAP = apList.length > 0 ? apList[Math.floor(Math.random() * apList.length)] : nodes[0];
      const assignedSSID = hostAP?.ssids ? hostAP.ssids[Math.floor(Math.random() * hostAP.ssids.length)] : undefined;
      const randomSpeed = wirelessSpeeds[Math.floor(Math.random() * wirelessSpeeds.length)];

      const angle = (Math.PI * 2 * i) / HARDWARE_POOL.length + (Math.random() * 0.5);
      const radius = 160 + Math.random() * 40;
      
      const newNode: Node = {
        id,
        type: dev.type,
        x: (hostAP?.x || 400) + Math.cos(angle) * radius,
        y: (hostAP?.y || 300) + Math.sin(angle) * radius,
        label: dev.label,
        status: Math.random() > 0.85 ? 'offline' : 'online',
        ip: randomIP(),
        vendor: dev.vendor,
        oui: lookupOUI(dev.vendor),
        parentId: hostAP?.id,
        signalStrength: Math.floor(Math.random() * 50) + 50,
        ssids: dev.type === 'router' ? ['SUBNET_GUEST'] : undefined
      };

      setNodes(prev => [...prev, newNode]);
      if (hostAP) {
        setConnections(prev => [...prev, {
          id: `c-scan-${id}`,
          from: hostAP.id,
          to: id,
          traffic: Math.random() * 15,
          type: 'wireless',
          ssid: assignedSSID,
          speed: randomSpeed
        }]);
      }
      
      setScanProgress(Math.round(((i + 1) / HARDWARE_POOL.length) * 100));
    }
    setIsScanning(false);
    setScanProgress(0);
  };

  return { isScanning, scanProgress, scanNetwork };
};
