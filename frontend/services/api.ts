
import { ApiDevice, ApiAlert, ApiScan, ScanCreateParams, ToolExecuteParams, ApiToolInfo } from '../types';

const API_BASE = 'http://127.0.0.1:8420/api';
const WS_URL = 'ws://127.0.0.1:8420/ws';

export class NetWatchApi {
  private static ws: WebSocket | null = null;
  private static handlers: Record<string, ((data: any) => void)[]> = {};
  private static apiKey: string | null = null;

  /** Set API key for authenticated requests */
  static setApiKey(key: string | null) {
    this.apiKey = key;
  }

  private static getHeaders(): HeadersInit {
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }
    return headers;
  }

  // ============ Devices ============

  static async getDevices(params?: { offset?: number; limit?: number; status?: string }): Promise<ApiDevice[]> {
    try {
      const query = new URLSearchParams();
      if (params?.offset) query.set('offset', String(params.offset));
      if (params?.limit) query.set('limit', String(params.limit));
      if (params?.status) query.set('status', params.status);

      const url = `${API_BASE}/devices${query.toString() ? '?' + query : ''}`;
      const res = await fetch(url, { headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to fetch devices');
      return await res.json();
    } catch (e) {
      console.warn("API Unavailable, using mock data fallback internally in hooks.");
      throw e;
    }
  }

  static async getDevice(deviceId: string): Promise<ApiDevice> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch device ${deviceId}`);
    return res.json();
  }

  static async updateDevice(deviceId: string, updates: Partial<Pick<ApiDevice, 'hostname' | 'device_type' | 'notes' | 'status'>>): Promise<ApiDevice> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw new Error(`Failed to update device ${deviceId}`);
    return res.json();
  }

  static async deleteDevice(deviceId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}`, {
      method: 'DELETE',
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Failed to delete device ${deviceId}`);
  }

  // ============ Scans ============

  static async launchScan(params: ScanCreateParams): Promise<ApiScan> {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        scan_type: params.scan_type,
        tool: params.tool,
        target: params.target,
        parameters: params.parameters
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Scan launch failed' }));
      throw new Error(err.detail || 'Scan launch failed');
    }
    return res.json();
  }

  static async getScans(params?: { offset?: number; limit?: number; status?: string }): Promise<ApiScan[]> {
    const query = new URLSearchParams();
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.status) query.set('status', params.status);

    const url = `${API_BASE}/scans${query.toString() ? '?' + query : ''}`;
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch scans');
    return res.json();
  }

  static async getScan(scanId: string): Promise<ApiScan> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch scan ${scanId}`);
    return res.json();
  }

  static async cancelScan(scanId: string): Promise<ApiScan> {
    const res = await fetch(`${API_BASE}/scans/${scanId}/cancel`, {
      method: 'POST',
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Failed to cancel scan ${scanId}`);
    return res.json();
  }

  // ============ Tools ============

  static async getTools(): Promise<ApiToolInfo[]> {
    const res = await fetch(`${API_BASE}/tools`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch tools');
    return res.json();
  }

  static async getTool(toolName: string): Promise<ApiToolInfo> {
    const res = await fetch(`${API_BASE}/tools/${toolName}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch tool ${toolName}`);
    return res.json();
  }

  static async getToolsHealth(): Promise<Array<{ name: string; status: string }>> {
    const res = await fetch(`${API_BASE}/tools/health`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch tools health');
    return res.json();
  }

  static async executeTool(toolName: string, task: string, params: Record<string, unknown> = {}): Promise<ToolExecuteParams> {
    const res = await fetch(`${API_BASE}/tools/${toolName}/execute`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ task, params })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Tool execution failed' }));
      throw new Error(err.detail || 'Tool execution failed');
    }
    return res.json();
  }

  // ============ Alerts ============

  static async getAlerts(params?: { severity?: string; status?: string; source_tool?: string; offset?: number; limit?: number }): Promise<ApiAlert[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    if (params?.source_tool) query.set('source_tool', params.source_tool);
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.limit) query.set('limit', String(params.limit));

    const url = `${API_BASE}/alerts${query.toString() ? '?' + query : ''}`;
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  }

  static async getAlert(alertId: string): Promise<ApiAlert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch alert ${alertId}`);
    return res.json();
  }

  static async getAlertStats(): Promise<Record<string, number>> {
    const res = await fetch(`${API_BASE}/alerts/stats`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch alert stats');
    return res.json();
  }

  static async updateAlert(alertId: string, updates: { status?: string; severity?: string; notes?: string }): Promise<ApiAlert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw new Error(`Failed to update alert ${alertId}`);
    return res.json();
  }

  // ============ System ============

  static async getSystemHealth(): Promise<{ status: string; version: string }> {
    const res = await fetch(`${API_BASE}/system/health`);  // No auth needed
    if (!res.ok) throw new Error('Failed to fetch system health');
    return res.json();
  }

  static async getSystemInfo(): Promise<Record<string, unknown>> {
    const res = await fetch(`${API_BASE}/system/info`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch system info');
    return res.json();
  }

  static connectWS() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;

    this.ws = new WebSocket(WS_URL);

    this.ws.onopen = () => {
      console.log('NetWatch Agent Connected');
      this.emit('system.startup', null);
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        // Assuming msg structure: { type: 'event.name', data: ... }
        if (msg.type) {
          this.emit(msg.type, msg.data);
        }
      } catch (e) {
        console.error('WS Parse Error', e);
      }
    };

    this.ws.onclose = () => {
      console.log('NetWatch Agent Disconnected');
      this.emit('system.shutdown', null);
      setTimeout(() => this.connectWS(), 5000); // Reconnect
    };
  }

  static on(event: string, handler: (data: any) => void) {
    if (!this.handlers[event]) this.handlers[event] = [];
    this.handlers[event].push(handler);
  }

  static off(event: string, handler: (data: any) => void) {
    if (!this.handlers[event]) return;
    this.handlers[event] = this.handlers[event].filter(h => h !== handler);
  }

  private static emit(event: string, data: any) {
    if (this.handlers[event]) {
      this.handlers[event].forEach(h => h(data));
    }
  }
}
