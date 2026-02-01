
export type NodeType = 'server' | 'firewall' | 'router' | 'database' | 'workstation' | 'mobile' | 'cloud' | 'iot' | 'extender' | 'group';

// ============ API Models (aligned with backend schemas) ============

export interface ApiPort {
  id: string;
  port_number: number;
  protocol: string;
  state: string;
  service_name?: string;
  service_version?: string;
  banner?: string;
}

export interface ApiDevice {
  id: string;
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  vendor?: string;
  os_family?: string;
  os_version?: string;
  device_type?: string;
  status: 'online' | 'offline' | 'warning' | 'compromised';
  first_seen: string;
  last_seen: string;
  notes?: string;
  ports: ApiPort[];
  created_at: string;
  updated_at: string;
}

export interface ApiAlert {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: string;
  source_tool: string;
  device_ip?: string;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface ApiScan {
  id: string;
  scan_type: string;
  tool: string;
  target: string;
  status: string;
  progress: number;
  started_at?: string;
  completed_at?: string;
  result_summary?: string;
  error_message?: string;
  parameters?: Record<string, unknown>;
  results?: Record<string, unknown>;
  devices_found: number;
  alerts_generated: number;
  created_at: string;
  updated_at: string;
}

export interface ApiToolInfo {
  name: string;
  display_name: string;
  category: string;
  description: string;
  version?: string;
  status: string;
  supported_tasks: string[];
}

// ============ Request/Response types ============

export interface ScanCreateParams {
  scan_type: 'network' | 'vulnerability' | 'traffic' | 'malware';
  tool: string;
  target: string;
  parameters?: Record<string, unknown>;
}

export interface ToolExecuteParams {
  tool: string;
  task: string;
  result: unknown;
}

// ============ WebSocket Event types ============

export interface WsDeviceEvent {
  device_id: string;
  ip: string;
  hostname?: string;
}

export interface WsScanEvent {
  scan_id: string;
  status?: string;
  progress?: number;
}

export interface WsAlertEvent {
  alert_id: string;
}

export interface Vulnerability {
  cve: string;
  cvss: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  references: string[];
}

export interface Node {
  id: string;
  type: NodeType;
  x: number;
  y: number;
  label: string;
  status: 'online' | 'offline' | 'warning' | 'compromised';
  ip: string;
  vendor?: string; // Brand/Manufacturer
  oui?: string; // Organizationally Unique Identifier
  parentId?: string;
  signalStrength?: number;
  ssids?: string[]; // Broadcasted networks
  width?: number; // For groups
  height?: number; // For groups
  ports?: number[]; // Open ports numbers for quick visual
  apiData?: ApiDevice; // Full API data reference
  vulnerabilities?: string[]; // Vulnerabilities found (simple list)
  detailedVulnerabilities?: Vulnerability[]; // Structured list
}

export interface Connection {
  id: string;
  from: string;
  to: string;
  traffic: number;
  type: 'wired' | 'wireless';
  ssid?: string;
  speed?: string;
}

// ============ Terminal types ============

export interface ShellInfo {
  id: string;
  name: string;
  path: string;
}

export type TerminalSessionState = 'idle' | 'creating' | 'connected' | 'error' | 'disconnected';

export interface TerminalTab {
  id: string;
  sessionId: string | null;
  shell: ShellInfo | null;
  state: TerminalSessionState;
  title: string;
}
