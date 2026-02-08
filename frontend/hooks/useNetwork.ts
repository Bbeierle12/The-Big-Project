
import { useState, useEffect, useCallback } from 'react';
import { Node, Connection, NodeType, ApiDevice, WsDeviceEvent } from '../types';
import { lookupOUI, randomIP, isValidCIDR } from '../utils/networkUtils';
import { NetWatchApi } from '../services/api';

const DEMO_MODE = import.meta.env.VITE_ENABLE_DEMO_DATA === 'true';

// Optional demo topology for offline mode.
const INITIAL_NODES: Node[] = [
  { 
    id: 'n1', type: 'cloud', x: 400, y: 80, label: 'ISP Gateway', status: 'online', 
    ip: '8.8.8.8', vendor: 'Juniper Networks', oui: lookupOUI('Juniper Networks') 
  },
  { 
    id: 'n2', 
    type: 'router', 
    x: 400, y: 220, 
    label: 'Main Router', 
    status: 'online', 
    ip: '192.168.1.1',
    vendor: 'ASUS (RT-AX88U)',
    oui: lookupOUI('ASUS (RT-AX88U)'),
    ssids: ['ARCHANGEL_SECURE', 'ARCHANGEL_GUEST', 'IOT_VLAN']
  }
];

const INITIAL_CONNECTIONS: Connection[] = [
  { id: 'c1', from: 'n1', to: 'n2', traffic: 80, type: 'wired', speed: '1 Gbps' }
];

const mapApiDeviceToNode = (device: ApiDevice, existingNode?: Node): Node => {
  // Heuristic to map API type to visual type
  let type: NodeType = 'workstation';
  const t = (device.device_type || '').toLowerCase();
  if (t.includes('router') || t.includes('gateway')) type = 'router';
  else if (t.includes('switch') || t.includes('bridge')) type = 'router'; // Visual simplification
  else if (t.includes('printer')) type = 'iot';
  else if (t.includes('camera') || t.includes('cam')) type = 'iot';
  else if (t.includes('phone') || t.includes('mobile')) type = 'mobile';
  else if (t.includes('server')) type = 'server';
  else if (t.includes('database')) type = 'database';
  
  // Position - if existing, keep it, else random around center
  const x = existingNode ? existingNode.x : 400 + (Math.random() * 400 - 200);
  const y = existingNode ? existingNode.y : 300 + (Math.random() * 300 - 150);

  return {
    id: device.id,
    type,
    x,
    y,
    label: device.hostname || device.ip_address,
    status: device.status,
    ip: device.ip_address,
    vendor: device.vendor,
    oui: lookupOUI(device.vendor || 'Generic'),
    ports: device.ports?.map(p => p.port_number),
    apiData: device,
    vulnerabilities: [] // Could map from separate API call
  };
};

export const useNetwork = () => {
  const [nodes, setNodes] = useState<Node[]>(DEMO_MODE ? INITIAL_NODES : []);
  const [connections, setConnections] = useState<Connection[]>(DEMO_MODE ? INITIAL_CONNECTIONS : []);
  const [isApiConnected, setIsApiConnected] = useState(false);

  // Initialize API and WS
  useEffect(() => {
    NetWatchApi.connectWS();
    
    const loadDevices = async () => {
      try {
        const devices = await NetWatchApi.getDevices();
        const newNodes = devices.map(d => mapApiDeviceToNode(d));
        if (newNodes.length > 0) {
          // Position nodes in a radial layout around gateway
          const gateway = newNodes.find(n => n.ip?.endsWith('.1')) || newNodes[0];
          const others = newNodes.filter(n => n.id !== gateway?.id);

          if (gateway) {
            gateway.x = 400;
            gateway.y = 200;
            gateway.type = 'router';
          }

          // Position other nodes in a circle around gateway
          others.forEach((node, i) => {
            const angle = (2 * Math.PI * i) / others.length;
            const radius = 180 + Math.random() * 60;
            node.x = 400 + Math.cos(angle) * radius;
            node.y = 350 + Math.sin(angle) * radius;
          });

          setNodes(newNodes);

          // Create connections from each device to gateway
          if (gateway) {
            const newConnections: Connection[] = others.map((node, i) => ({
              id: `conn-${node.id}`,
              from: gateway.id,
              to: node.id,
              traffic: Math.random() * 30,
              type: 'wireless' as const,
              speed: '100 Mbps'
            }));
            setConnections(newConnections);
          }
        } else if (!DEMO_MODE) {
          setNodes([]);
          setConnections([]);
        }
        setIsApiConnected(true);
      } catch (e) {
        setIsApiConnected(false);
        if (!DEMO_MODE) {
          setNodes([]);
          setConnections([]);
        }
      }
    };
    loadDevices();

    // WS Event Listeners
    // Backend sends minimal payloads (device_id, ip, hostname), so we hydrate by fetching full data
    const handleDeviceDiscovered = async (evt: WsDeviceEvent) => {
      try {
        const device = await NetWatchApi.getDevice(evt.device_id);
        const newNode = mapApiDeviceToNode(device);

        setNodes(prev => {
          if (prev.find(n => n.id === device.id)) return prev;

          // Find gateway to position relative to it
          const gateway = prev.find(n => n.ip?.endsWith('.1') || n.type === 'router');
          if (gateway) {
            const angle = Math.random() * 2 * Math.PI;
            const radius = 180 + Math.random() * 60;
            newNode.x = gateway.x + Math.cos(angle) * radius;
            newNode.y = gateway.y + 150 + Math.sin(angle) * radius;
          }

          return [...prev, newNode];
        });

        // Create connection to gateway (get gateway from updated nodes state)
        setNodes(currentNodes => {
          const gatewayNode = currentNodes.find(n => n.ip?.endsWith('.1') || n.type === 'router');
          if (gatewayNode && device.id !== gatewayNode.id) {
            setConnections(prev => {
              if (prev.find(c => c.to === device.id)) return prev;
              return [...prev, {
                id: `conn-${device.id}`,
                from: gatewayNode.id,
                to: device.id,
                traffic: Math.random() * 30,
                type: 'wireless' as const,
                speed: '100 Mbps'
              }];
            });
          }
          return currentNodes; // Don't change nodes, just reading
        });
      } catch (e) {
        console.warn('Failed to hydrate discovered device:', evt.device_id, e);
        // Fallback: add minimal node with just the info we have
        setNodes(prev => {
          if (prev.find(n => n.id === evt.device_id)) return prev;
          const minimalNode: Node = {
            id: evt.device_id,
            type: 'workstation',
            x: 400 + (Math.random() * 400 - 200),
            y: 300 + (Math.random() * 300 - 150),
            label: evt.hostname || evt.ip,
            status: 'online',
            ip: evt.ip,
          };
          return [...prev, minimalNode];
        });
      }
    };

    const handleDeviceUpdated = async (evt: WsDeviceEvent) => {
      try {
        const device = await NetWatchApi.getDevice(evt.device_id);
        setNodes(prev => prev.map(n =>
          n.id === device.id ? mapApiDeviceToNode(device, n) : n
        ));
      } catch (e) {
        console.warn('Failed to hydrate updated device:', evt.device_id, e);
      }
    };

    const handleDeviceOffline = (evt: WsDeviceEvent | string) => {
      // Backend might send just ID or an event object
      const deviceId = typeof evt === 'string' ? evt : evt.device_id;
      setNodes(prev => prev.map(n =>
        n.id === deviceId ? { ...n, status: 'offline' } : n
      ));
    };

    NetWatchApi.on('device.discovered', handleDeviceDiscovered);
    NetWatchApi.on('device.updated', handleDeviceUpdated);
    NetWatchApi.on('device.offline', handleDeviceOffline);
    NetWatchApi.on('system.startup', () => setIsApiConnected(true));
    NetWatchApi.on('system.shutdown', () => setIsApiConnected(false));

    return () => {
      NetWatchApi.off('device.discovered', handleDeviceDiscovered);
      NetWatchApi.off('device.updated', handleDeviceUpdated);
      NetWatchApi.off('device.offline', handleDeviceOffline);
    };
  }, []);

  // Traffic Simulation Effect (keep visuals alive)
  useEffect(() => {
    const interval = setInterval(() => {
      setConnections(prev => prev.map(c => ({
        ...c,
        traffic: Math.max(0, Math.min(100, c.traffic + (Math.random() * 10 - 5)))
      })));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const addNode = (type: NodeType, pan: {x: number, y: number}) => {
    // Local addition only (visualizer mode) unless we have a "Create Device" API
    const id = `n-${Date.now()}`;
    const centerX = 400 - pan.x; 
    const centerY = 300 - pan.y;
    
    const newNode: Node = { 
      id, type, 
      x: centerX + (Math.random() * 50 - 25), 
      y: centerY + (Math.random() * 50 - 25), 
      label: `New ${type}`, 
      status: 'online',
      ip: randomIP(),
      vendor: 'Generic Hardware',
      oui: lookupOUI('Generic Hardware'),
      ssids: (type === 'router' || type === 'extender') ? ['NEW_WIFI_SIGNAL'] : undefined
    };
    
    setNodes(prev => [...prev, newNode]);
    return id;
  };

  const createGroup = (selectedIds: string[]) => {
    if (selectedIds.length < 2) return null;
    
    const selectedNodes = nodes.filter(n => selectedIds.includes(n.id));
    const minX = Math.min(...selectedNodes.map(n => n.x));
    const minY = Math.min(...selectedNodes.map(n => n.y));
    const maxX = Math.max(...selectedNodes.map(n => n.x));
    const maxY = Math.max(...selectedNodes.map(n => n.y));
    
    const padding = 60;
    const groupX = minX - padding;
    const groupY = minY - padding;
    const groupW = (maxX - minX) + (padding * 2);
    const groupH = (maxY - minY) + (padding * 2);

    const defaultSubnet = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.0/24`;
    const subnet = window.prompt("Assign Network CIDR (e.g., 10.0.0.0/24):", defaultSubnet);
    
    if (subnet === null) return null;

    if (!isValidCIDR(subnet)) {
      alert("Invalid CIDR format.");
      return null;
    }

    const groupId = `g-${Date.now()}`;
    const groupNode: Node = {
      id: groupId,
      type: 'group',
      x: groupX,
      y: groupY,
      width: groupW,
      height: groupH,
      label: 'New Cluster',
      status: 'online',
      ip: subnet
    };

    const updatedNodes = nodes.map(n => {
      if (selectedIds.includes(n.id)) {
        return { ...n, parentId: groupId };
      }
      return n;
    });

    setNodes([...updatedNodes, groupNode]);
    return groupId;
  };

  const deleteSelection = (selectedIds: string[]) => {
    // In a real app, this would likely call DELETE /api/devices/{id}
    if (selectedIds.length === 0) return;
    
    const groupsToDelete = nodes.filter(n => selectedIds.includes(n.id) && n.type === 'group');
    const groupIds = groupsToDelete.map(g => g.id);
    
    let nextNodes = nodes.filter(n => !selectedIds.includes(n.id));
    
    if (groupIds.length > 0) {
      nextNodes = nextNodes.map(n => {
        if (n.parentId && groupIds.includes(n.parentId)) {
          return { ...n, parentId: undefined };
        }
        return n;
      });
    }

    setNodes(nextNodes);
    setConnections(connections.filter(c => !selectedIds.includes(c.from) && !selectedIds.includes(c.to)));
  };

  const saveTopology = () => {
    try {
      const payload = JSON.stringify({ nodes, connections });
      localStorage.setItem('archangel_topology', payload);
      alert('Network topology saved to local storage.');
    } catch (e) {
      alert('Failed to save topology.');
    }
  };

  const loadTopology = () => {
    try {
      const data = localStorage.getItem('archangel_topology');
      if (data) {
        const parsed = JSON.parse(data);
        if (Array.isArray(parsed.nodes) && Array.isArray(parsed.connections)) {
          setNodes(parsed.nodes);
          setConnections(parsed.connections);
          alert('Network topology loaded.');
          return true;
        } else {
          alert('Saved data is invalid.');
        }
      } else {
        alert('No saved topology found.');
      }
    } catch (e) {
      alert('Error loading topology.');
    }
    return false;
  };

  return {
    nodes,
    setNodes,
    connections,
    setConnections,
    addNode,
    createGroup,
    deleteSelection,
    saveTopology,
    loadTopology
  };
};
