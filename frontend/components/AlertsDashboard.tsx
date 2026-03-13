import React, { startTransition, useEffect, useState } from 'react';
import { AlertTriangle, BellRing, CheckCircle2, Filter } from 'lucide-react';
import { ApiAlert, AlertStats } from '../types';
import { NetWatchApi } from '../services/api';

function severityTone(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'border-red-500/30 bg-red-500/10 text-red-300';
    case 'high':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-300';
    case 'medium':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
    case 'low':
      return 'border-blue-500/30 bg-blue-500/10 text-blue-300';
    default:
      return 'border-slate-500/30 bg-slate-500/10 text-slate-300';
  }
}

export const AlertsDashboard: React.FC = () => {
  const [alerts, setAlerts] = useState<ApiAlert[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<string>('all');

  useEffect(() => {
    let active = true;
    const load = async (showLoading = true) => {
      if (showLoading) setLoading(true);
      setError(null);
      try {
        const [nextAlerts, nextStats] = await Promise.all([
          NetWatchApi.getAlerts({ limit: 50, severity: severity === 'all' ? undefined : severity }),
          NetWatchApi.getAlertStats(),
        ]);
        if (!active) return;
        startTransition(() => {
          setAlerts(nextAlerts);
          setStats(nextStats);
        });
      } catch (e: any) {
        if (!active) return;
        setError(e?.message || 'Failed to load alerts');
      } finally {
        if (active && showLoading) setLoading(false);
      }
    };
    void load();
    const intervalId = window.setInterval(() => {
      void load(false);
    }, 15000);
    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, [severity]);

  const openTotal = stats ? Object.values(stats.open_by_severity).reduce((sum, count) => sum + count, 0) : 0;

  return (
    <div className="h-full overflow-y-auto bg-[#05070a]">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 p-6">
        <div className="rounded-lg border border-white/10 bg-black/20 p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="text-[11px] font-black uppercase tracking-[0.35em] text-red-300">Alerts</div>
              <h2 className="mt-3 text-3xl font-black uppercase tracking-tight text-white">Unified Findings Queue</h2>
              <p className="mt-2 max-w-3xl text-sm text-slate-400">
                Cross-tool alerts from network scans, Sentinel, and other adapters land here. This is the shared triage surface.
              </p>
            </div>
            <div className="flex items-center gap-2 rounded border border-white/10 bg-black/30 px-4 py-3">
              <Filter size={14} className="text-slate-500" />
              <select
                className="bg-transparent text-xs font-bold uppercase tracking-wider text-white outline-none"
                value={severity}
                onChange={(event) => setSeverity(event.target.value)}
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-4">
          <div className="rounded border border-red-500/20 bg-red-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-red-300">Open</div>
            <div className="mt-3 text-3xl font-black text-white">{openTotal}</div>
          </div>
          <div className="rounded border border-orange-500/20 bg-orange-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-orange-300">Critical</div>
            <div className="mt-3 text-3xl font-black text-white">{stats?.open_by_severity.critical ?? 0}</div>
          </div>
          <div className="rounded border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-amber-300">High</div>
            <div className="mt-3 text-3xl font-black text-white">{stats?.open_by_severity.high ?? 0}</div>
          </div>
          <div className="rounded border border-cyan-500/20 bg-cyan-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-cyan-300">Sources</div>
            <div className="mt-3 text-3xl font-black text-white">{stats ? Object.keys(stats.open_by_tool).length : 0}</div>
          </div>
        </div>

        <div className="rounded-lg border border-white/10 bg-black/20 p-5">
          <div className="flex items-center gap-2">
            <BellRing size={16} className="text-cyan-300" />
            <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Recent Alerts</h3>
          </div>
          <div className="mt-4 space-y-3">
            {loading ? (
              <div className="text-sm text-slate-500">Loading alerts...</div>
            ) : error ? (
              <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>
            ) : alerts.length === 0 ? (
              <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">No alerts match the current filter.</div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} className="rounded border border-white/10 bg-white/[0.03] p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <AlertTriangle size={14} className="text-red-300" />
                        <div className="text-sm font-bold text-white">{alert.title}</div>
                      </div>
                      <div className="mt-2 text-sm text-slate-400">{alert.description || 'No description provided.'}</div>
                      <div className="mt-3 flex flex-wrap gap-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        <span>Tool: {alert.source_tool}</span>
                        <span>Status: {alert.status}</span>
                        <span>Count: {alert.count}</span>
                        {alert.device_ip && <span>IP: {alert.device_ip}</span>}
                        <span>Last Seen: {new Date(alert.last_seen).toLocaleString()}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {alert.status === 'resolved' ? (
                        <CheckCircle2 size={16} className="text-emerald-400" />
                      ) : null}
                      <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${severityTone(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
