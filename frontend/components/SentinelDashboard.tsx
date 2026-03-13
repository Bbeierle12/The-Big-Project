import React, { startTransition, useEffect, useState } from 'react';
import {
  Activity,
  Database,
  FileWarning,
  RefreshCcw,
  Shield,
  ShieldAlert,
  Siren,
  X,
} from 'lucide-react';
import { ApiAlert, SentinelStatus, SentinelVulnerabilityMatch } from '../types';
import { NetWatchApi } from '../services/api';

interface SentinelDashboardProps {
  onClose?: () => void;
  onShowVulnReport: () => void;
  embedded?: boolean;
}

type BusyAction = 'collect' | 'correlate' | 'feeds' | 'vulns' | null;

const SNAPSHOT_LABELS: Array<{ key: keyof SentinelStatus['snapshots']; label: string; accent: string }> = [
  { key: 'network', label: 'Network', accent: 'text-cyan-400' },
  { key: 'file_hashes', label: 'File Integrity', accent: 'text-amber-400' },
  { key: 'metrics', label: 'System Metrics', accent: 'text-emerald-400' },
  { key: 'process', label: 'Process', accent: 'text-slate-400' },
  { key: 'auth', label: 'Auth', accent: 'text-slate-400' },
  { key: 'persistence', label: 'Persistence', accent: 'text-slate-400' },
];

function formatTimestamp(value?: string | null) {
  if (!value) return 'Awaiting data';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatAge(value?: string | null) {
  if (!value) return 'Never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unknown';
  const diffMs = Date.now() - date.getTime();
  const diffMinutes = Math.max(Math.floor(diffMs / 60000), 0);
  if (diffMinutes < 1) return 'Just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

function severityClasses(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'border-red-500/40 bg-red-500/10 text-red-300';
    case 'high':
      return 'border-orange-500/40 bg-orange-500/10 text-orange-300';
    case 'medium':
      return 'border-amber-500/40 bg-amber-500/10 text-amber-300';
    case 'low':
      return 'border-blue-500/40 bg-blue-500/10 text-blue-300';
    default:
      return 'border-slate-500/30 bg-slate-500/10 text-slate-300';
  }
}

export const SentinelDashboard: React.FC<SentinelDashboardProps> = ({ onClose, onShowVulnReport, embedded = false }) => {
  const [status, setStatus] = useState<SentinelStatus | null>(null);
  const [alerts, setAlerts] = useState<ApiAlert[]>([]);
  const [vulns, setVulns] = useState<SentinelVulnerabilityMatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<BusyAction>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadDashboard = async (showLoading = true) => {
    if (showLoading) setLoading(true);
    setError(null);
    try {
      const [nextStatus, nextAlerts, nextVulns] = await Promise.all([
        NetWatchApi.getSentinelStatus(),
        NetWatchApi.getAlerts({ source_tool: 'sentinel', limit: 25 }),
        NetWatchApi.getSentinelVulns(25),
      ]);
      startTransition(() => {
        setStatus(nextStatus);
        setAlerts(nextAlerts);
        setVulns(nextVulns.rows);
      });
    } catch (e: any) {
      setError(e?.message || 'Failed to load Sentinel dashboard');
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  useEffect(() => {
    void loadDashboard();
    const intervalId = window.setInterval(() => {
      void loadDashboard(false);
    }, 30000);
    return () => window.clearInterval(intervalId);
  }, []);

  useEffect(() => {
    const handleAlertCreated = (event: ApiAlert) => {
      if (event?.source_tool === 'sentinel') {
        void loadDashboard(false);
      }
    };
    NetWatchApi.on('alert.created', handleAlertCreated);
    return () => NetWatchApi.off('alert.created', handleAlertCreated);
  }, []);

  const runAction = async (action: BusyAction, executor: () => Promise<any>, successMessage: (result: any) => string) => {
    setBusyAction(action);
    setActionMessage(null);
    setError(null);
    try {
      const result = await executor();
      await loadDashboard(false);
      setActionMessage(successMessage(result));
    } catch (e: any) {
      setError(e?.message || 'Sentinel action failed');
    } finally {
      setBusyAction(null);
    }
  };

  const latestSnapshot = status ? Object.values(status.snapshots).filter(Boolean).sort().at(-1) ?? null : null;
  const openAlerts = alerts.filter(alert => alert.status !== 'resolved' && alert.status !== 'false_positive');
  const criticalAlerts = openAlerts.filter(alert => alert.severity === 'critical');
  const totalIocs = status ? Object.values(status.feeds.ioc_counts).reduce((sum, count) => sum + count, 0) : 0;
  const feedEntries = status ? Object.values(status.feeds.metadata).sort((a, b) => a.name.localeCompare(b.name)) : [];
  const outerClass = embedded
    ? 'h-full overflow-y-auto bg-[#05070a]'
    : 'fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-10 backdrop-blur-sm';
  const innerClass = embedded
    ? 'mx-auto flex min-h-full w-full max-w-7xl flex-col overflow-hidden'
    : 'flex h-full w-full max-w-7xl flex-col overflow-hidden rounded-lg border border-white/10 bg-[#05070a] shadow-2xl';

  return (
    <div className={outerClass}>
      <div className={innerClass}>
        <div className="flex items-center justify-between border-b border-white/10 bg-black/40 px-6 py-4">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
              <Shield size={22} />
            </div>
            <div>
              <h2 className="text-xl font-bold uppercase tracking-tight text-white">Desktop Safety Monitor</h2>
              <p className="text-xs font-mono uppercase tracking-[0.3em] text-slate-500">
                Sentinel host telemetry, threat intelligence, and live findings
              </p>
            </div>
          </div>
          {embedded ? null : (
            <button
              onClick={onClose}
              className="rounded-full p-2 text-slate-500 transition-colors hover:bg-white/10 hover:text-white"
            >
              <X size={22} />
            </button>
          )}
        </div>

        <div className="border-b border-white/10 bg-[#060b11] px-6 py-4">
          <div className="grid gap-3 lg:grid-cols-4">
            <div className="rounded border border-cyan-500/20 bg-cyan-500/5 p-4">
              <div className="text-[10px] font-black uppercase tracking-[0.25em] text-cyan-400">Open Findings</div>
              <div className="mt-2 flex items-end gap-3">
                <span className="text-3xl font-black text-white">{openAlerts.length}</span>
                <span className="pb-1 text-xs font-bold uppercase tracking-wider text-slate-500">
                  {criticalAlerts.length} critical
                </span>
              </div>
            </div>
            <div className="rounded border border-emerald-500/20 bg-emerald-500/5 p-4">
              <div className="text-[10px] font-black uppercase tracking-[0.25em] text-emerald-400">Threat Intel</div>
              <div className="mt-2 flex items-end gap-3">
                <span className="text-3xl font-black text-white">{totalIocs.toLocaleString()}</span>
                <span className="pb-1 text-xs font-bold uppercase tracking-wider text-slate-500">local IOCs</span>
              </div>
            </div>
            <div className="rounded border border-amber-500/20 bg-amber-500/5 p-4">
              <div className="text-[10px] font-black uppercase tracking-[0.25em] text-amber-400">Package Exposure</div>
              <div className="mt-2 flex items-end gap-3">
                <span className="text-3xl font-black text-white">{vulns.length}</span>
                <span className="pb-1 text-xs font-bold uppercase tracking-wider text-slate-500">recent matches</span>
              </div>
            </div>
            <div className="rounded border border-white/10 bg-white/5 p-4">
              <div className="text-[10px] font-black uppercase tracking-[0.25em] text-slate-400">Last Collection</div>
              <div className="mt-2 text-lg font-bold text-white">{formatAge(latestSnapshot)}</div>
              <div className="mt-1 text-xs text-slate-500">{formatTimestamp(latestSnapshot)}</div>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              onClick={() => void runAction('collect', () => NetWatchApi.collectSentinel(), (result) => `Collected ${Object.values(result.counts || {}).reduce((sum, value) => sum + Number(value || 0), 0)} snapshot rows.`)}
              disabled={busyAction !== null}
              className="flex items-center gap-2 rounded border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-xs font-bold uppercase tracking-wider text-cyan-300 transition-colors hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Activity size={14} className={busyAction === 'collect' ? 'animate-spin' : ''} />
              Collect Snapshot
            </button>
            <button
              onClick={() => void runAction('correlate', () => NetWatchApi.correlateSentinel({ refresh_feeds: true, scan_vulns: true, ingest_alerts: true }), (result) => `Correlated ${result.count} findings. Created ${result.ingestion?.created ?? 0} alerts.`)}
              disabled={busyAction !== null}
              className="flex items-center gap-2 rounded border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs font-bold uppercase tracking-wider text-red-300 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Siren size={14} className={busyAction === 'correlate' ? 'animate-pulse' : ''} />
              Correlate Threats
            </button>
            <button
              onClick={() => void runAction('feeds', () => NetWatchApi.refreshSentinelFeeds(true), () => 'Threat intelligence feeds refreshed.')}
              disabled={busyAction !== null}
              className="flex items-center gap-2 rounded border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-bold uppercase tracking-wider text-emerald-300 transition-colors hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RefreshCcw size={14} className={busyAction === 'feeds' ? 'animate-spin' : ''} />
              Refresh Feeds
            </button>
            <button
              onClick={() => void runAction('vulns', () => NetWatchApi.scanSentinelVulns({ force: false, refresh_feeds: true }), (result) => `Package scan complete. ${result.count ?? 0} matches in current window.`)}
              disabled={busyAction !== null}
              className="flex items-center gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs font-bold uppercase tracking-wider text-amber-300 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <FileWarning size={14} className={busyAction === 'vulns' ? 'animate-pulse' : ''} />
              Scan Packages
            </button>
            <button
              onClick={onShowVulnReport}
              className="ml-auto flex items-center gap-2 rounded border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold uppercase tracking-wider text-white transition-colors hover:bg-white/10"
            >
              <ShieldAlert size={14} />
              Vulnerability Workspace
            </button>
          </div>

          {(actionMessage || error) && (
            <div className={`mt-4 rounded border px-4 py-3 text-sm ${error ? 'border-red-500/30 bg-red-500/10 text-red-200' : 'border-cyan-500/20 bg-cyan-500/10 text-cyan-100'}`}>
              {error || actionMessage}
            </div>
          )}
        </div>

        <div className="grid flex-1 gap-0 overflow-hidden xl:grid-cols-[1.15fr_0.85fr]">
          <div className="flex min-h-0 flex-col border-r border-white/10">
            <div className="grid gap-3 border-b border-white/10 bg-black/20 p-6 md:grid-cols-2 xl:grid-cols-3">
              {SNAPSHOT_LABELS.map((snapshot) => {
                const value = status?.snapshots[snapshot.key] ?? null;
                return (
                  <div key={snapshot.key} className="rounded border border-white/10 bg-white/[0.03] p-4">
                    <div className={`text-[10px] font-black uppercase tracking-[0.25em] ${snapshot.accent}`}>
                      {snapshot.label}
                    </div>
                    <div className="mt-2 text-sm font-bold text-white">{formatAge(value)}</div>
                    <div className="mt-1 text-xs text-slate-500">{formatTimestamp(value)}</div>
                  </div>
                );
              })}
            </div>

            <div className="grid min-h-0 flex-1 gap-0 lg:grid-cols-2">
              <div className="min-h-0 border-r border-white/10">
                <div className="border-b border-white/10 px-6 py-4">
                  <div className="text-sm font-bold uppercase tracking-wider text-white">Sentinel Alerts</div>
                  <div className="mt-1 text-xs text-slate-500">Live findings routed into the main alert pipeline.</div>
                </div>
                <div className="h-full overflow-y-auto p-4">
                  {loading ? (
                    <div className="p-4 text-sm text-slate-500">Loading Sentinel alerts...</div>
                  ) : alerts.length === 0 ? (
                    <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
                      No Sentinel alerts yet. Run collection and correlation to establish baseline coverage.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {alerts.map((alert) => (
                        <div key={alert.id} className="rounded border border-white/10 bg-white/[0.03] p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="text-sm font-bold text-white">{alert.title}</div>
                              <div className="mt-1 text-xs leading-relaxed text-slate-400">{alert.description}</div>
                            </div>
                            <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${severityClasses(alert.severity)}`}>
                              {alert.severity}
                            </span>
                          </div>
                          <div className="mt-3 flex flex-wrap items-center gap-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                            <span>Status: {alert.status}</span>
                            <span>Count: {alert.count}</span>
                            {alert.device_ip && <span>IP: {alert.device_ip}</span>}
                            <span>Seen: {formatAge(alert.last_seen)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="min-h-0">
                <div className="border-b border-white/10 px-6 py-4">
                  <div className="text-sm font-bold uppercase tracking-wider text-white">Package Exposure</div>
                  <div className="mt-1 text-xs text-slate-500">Recent OSV and KEV matches found on this workstation.</div>
                </div>
                <div className="h-full overflow-y-auto p-4">
                  {loading ? (
                    <div className="p-4 text-sm text-slate-500">Loading vulnerability matches...</div>
                  ) : vulns.length === 0 ? (
                    <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
                      No package matches in the current Sentinel vuln window.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {vulns.map((match) => (
                        <div key={match.id} className="rounded border border-white/10 bg-white/[0.03] p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="text-sm font-bold text-white">{match.package}</div>
                              <div className="mt-1 text-xs font-mono text-slate-500">{match.version}</div>
                            </div>
                            <div className="flex flex-col items-end gap-2">
                              <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${severityClasses(match.severity)}`}>
                                {match.severity}
                              </span>
                              {Boolean(match.exploited) && (
                                <span className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1 text-[10px] font-black uppercase tracking-wider text-red-300">
                                  KEV
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="mt-3 flex items-center justify-between gap-3">
                            <div className="text-xs font-bold text-cyan-300">{match.cve_id}</div>
                            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                              {formatAge(match.timestamp)}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="flex min-h-0 flex-col bg-[#040608]">
            <div className="border-b border-white/10 px-6 py-4">
              <div className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-white">
                <Database size={15} className="text-emerald-400" />
                Feed Inventory
              </div>
              <div className="mt-1 text-xs text-slate-500">Bulk feeds and cached IOC tables loaded into Sentinel.</div>
            </div>

            <div className="border-b border-white/10 p-6">
              <div className="grid gap-3 sm:grid-cols-2">
                {Object.entries(status?.feeds.ioc_counts ?? {}).map(([key, value]) => (
                  <div key={key} className="rounded border border-white/10 bg-white/[0.03] p-4">
                    <div className="text-[10px] font-black uppercase tracking-[0.25em] text-slate-500">
                      {key.replace('sentinel_ioc_', '').replace('_', ' ')}
                    </div>
                    <div className="mt-2 text-2xl font-black text-white">{value.toLocaleString()}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto p-4">
              <div className="space-y-3">
                {feedEntries.length === 0 ? (
                  <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
                    No feed metadata yet. Refresh feeds to populate local IOC inventory.
                  </div>
                ) : (
                  feedEntries.map((feed) => (
                    <div key={feed.name} className="rounded border border-white/10 bg-white/[0.03] p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="text-sm font-bold uppercase tracking-wider text-white">{feed.name}</div>
                          <div className="mt-1 text-xs text-slate-500">
                            {feed.message || 'ready'} · updated {formatAge(feed.updated_at)}
                          </div>
                        </div>
                        <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${
                          feed.status === 'updated'
                            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                            : feed.status === 'error'
                              ? 'border-red-500/30 bg-red-500/10 text-red-300'
                              : 'border-slate-500/30 bg-slate-500/10 text-slate-300'
                        }`}>
                          {feed.status}
                        </span>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {Object.entries(feed.counts || {}).map(([key, value]) => (
                          <span key={key} className="rounded bg-black/40 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                            {key.replace('sentinel_ioc_', '')}: {value}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="border-t border-white/10 px-6 py-4 text-[11px] text-slate-500">
              Sentinel currently surfaces network, file integrity, metrics, OSINT, and vulnerability coverage in this repo. Process, auth, and persistence collection are still pending integration.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
