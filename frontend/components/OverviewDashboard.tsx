import React, { startTransition, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Boxes,
  Laptop,
  Network,
  ShieldAlert,
  TerminalSquare,
} from 'lucide-react';
import { ApiAlert, ApiScan, AlertStats, AppModule, SentinelStatus } from '../types';
import { NetWatchApi } from '../services/api';

interface OverviewDashboardProps {
  onSelectModule: (module: AppModule) => void;
}

interface OverviewData {
  health: { status: string; version: string };
  alerts: ApiAlert[];
  alertStats: AlertStats;
  scans: ApiScan[];
  sentinel: SentinelStatus;
  toolsHealth: Array<{ name: string; status: string }>;
}

const MODULE_CARDS: Array<{
  module: AppModule;
  title: string;
  description: string;
  accent: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
}> = [
  {
    module: 'network',
    title: 'Network',
    description: 'Topology, scans, device inspection, and traffic workflows.',
    accent: 'from-cyan-500/20 to-cyan-950/20 border-cyan-500/20 text-cyan-300',
    icon: Network,
  },
  {
    module: 'desktop_safety',
    title: 'Desktop Safety',
    description: 'Sentinel host telemetry, package exposure, and workstation findings.',
    accent: 'from-emerald-500/20 to-emerald-950/20 border-emerald-500/20 text-emerald-300',
    icon: Laptop,
  },
  {
    module: 'vulnerabilities',
    title: 'Vulnerabilities',
    description: 'Cross-tool CVE triage plus Sentinel package matches.',
    accent: 'from-amber-500/20 to-amber-950/20 border-amber-500/20 text-amber-300',
    icon: ShieldAlert,
  },
  {
    module: 'alerts',
    title: 'Alerts',
    description: 'Unified queue of open findings across the platform.',
    accent: 'from-red-500/20 to-red-950/20 border-red-500/20 text-red-300',
    icon: AlertTriangle,
  },
];

function formatTime(value?: string | null) {
  if (!value) return 'No activity yet';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function severityTone(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'border-red-500/30 bg-red-500/10 text-red-300';
    case 'high':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-300';
    case 'medium':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
    default:
      return 'border-slate-500/30 bg-slate-500/10 text-slate-300';
  }
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({ onSelectModule }) => {
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    const load = async (showLoading = true) => {
      if (showLoading) setLoading(true);
      setError(null);
      try {
        const overview = await NetWatchApi.getOverview();
        if (!active) return;
        startTransition(() => {
          setData({
            health: overview.health,
            alerts: overview.alerts,
            alertStats: overview.alert_stats,
            scans: overview.scans,
            sentinel: overview.sentinel,
            toolsHealth: overview.tools_health,
          });
        });
      } catch (e: any) {
        if (!active) return;
        setError(e?.message || 'Failed to load overview');
      } finally {
        if (active && showLoading) setLoading(false);
      }
    };

    void load();
    const intervalId = window.setInterval(() => {
      void load(false);
    }, 30000);
    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, []);

  const openAlerts = data ? Object.values(data.alertStats.open_by_severity).reduce((sum, count) => sum + count, 0) : 0;
  const criticalAlerts = data?.alertStats.open_by_severity.critical ?? 0;
  const availableTools = data?.toolsHealth.filter((tool) => tool.status === 'available').length ?? 0;
  const totalTools = data?.toolsHealth.length ?? 0;
  const lastSentinelActivity = data ? Object.values(data.sentinel.snapshots).filter(Boolean).sort().at(-1) ?? null : null;

  return (
    <div className="h-full overflow-y-auto bg-[#05070a]">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 p-6">
        <div className="rounded-lg border border-white/10 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.08),_transparent_35%),linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0))] p-6">
          <div className="flex flex-wrap items-start justify-between gap-6">
            <div>
              <div className="text-[11px] font-black uppercase tracking-[0.35em] text-cyan-400">Overview</div>
              <h2 className="mt-3 text-3xl font-black uppercase tracking-tight text-white">Security Platform Control Surface</h2>
              <p className="mt-2 max-w-3xl text-sm text-slate-400">
                One backend, multiple operator modules. Use this view to see what needs attention now, then jump into the matching workspace.
              </p>
            </div>
            <div className="rounded border border-white/10 bg-black/30 px-4 py-3 text-right">
              <div className="text-[10px] font-black uppercase tracking-[0.25em] text-slate-500">Backend</div>
              <div className="mt-2 text-xl font-bold text-white">{data?.health.status ?? 'Loading...'}</div>
              <div className="mt-1 text-xs text-slate-500">v{data?.health.version ?? '0.0.0'}</div>
            </div>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-4">
          <div className="rounded border border-red-500/20 bg-red-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-red-300">Open Alerts</div>
            <div className="mt-3 flex items-end gap-3">
              <span className="text-3xl font-black text-white">{openAlerts}</span>
              <span className="pb-1 text-xs font-bold uppercase tracking-wider text-slate-500">{criticalAlerts} critical</span>
            </div>
          </div>
          <div className="rounded border border-cyan-500/20 bg-cyan-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-cyan-300">Tool Coverage</div>
            <div className="mt-3 flex items-end gap-3">
              <span className="text-3xl font-black text-white">{availableTools}</span>
              <span className="pb-1 text-xs font-bold uppercase tracking-wider text-slate-500">of {totalTools} available</span>
            </div>
          </div>
          <div className="rounded border border-emerald-500/20 bg-emerald-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-emerald-300">Sentinel Activity</div>
            <div className="mt-3 text-lg font-bold text-white">{formatTime(lastSentinelActivity)}</div>
          </div>
          <div className="rounded border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-amber-300">Latest Scan</div>
            <div className="mt-3 text-sm font-bold text-white">{data?.scans[0]?.target ?? 'No scans yet'}</div>
            <div className="mt-1 text-xs text-slate-500">{data?.scans[0]?.result_summary ?? 'Awaiting scan activity'}</div>
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-lg border border-white/10 bg-black/20 p-5">
            <div className="flex items-center gap-2">
              <Boxes size={16} className="text-cyan-400" />
              <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Modules</h3>
            </div>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              {MODULE_CARDS.map((card) => {
                const Icon = card.icon;
                return (
                  <button
                    key={card.module}
                    onClick={() => onSelectModule(card.module)}
                    className={`group rounded-lg border bg-gradient-to-br p-5 text-left transition-all hover:-translate-y-0.5 hover:bg-white/5 ${card.accent}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <Icon size={18} className="shrink-0" />
                      <ArrowRight size={16} className="text-white/30 transition-transform group-hover:translate-x-1" />
                    </div>
                    <div className="mt-4 text-lg font-black uppercase tracking-tight text-white">{card.title}</div>
                    <div className="mt-2 text-sm leading-relaxed text-slate-400">{card.description}</div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="rounded-lg border border-white/10 bg-black/20 p-5">
            <div className="flex items-center gap-2">
              <Activity size={16} className="text-emerald-400" />
              <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Recent Activity</h3>
            </div>
            <div className="mt-4 space-y-3">
              {loading ? (
                <div className="text-sm text-slate-500">Loading overview...</div>
              ) : error ? (
                <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>
              ) : (
                <>
                  {(data?.alerts.length ?? 0) === 0 ? (
                    <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
                      No recent alerts.
                    </div>
                  ) : (
                    data?.alerts.map((alert) => (
                      <div key={alert.id} className="rounded border border-white/10 bg-white/[0.03] p-4">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="text-sm font-bold text-white">{alert.title}</div>
                            <div className="mt-1 text-xs text-slate-500">{alert.source_tool} · {formatTime(alert.last_seen)}</div>
                          </div>
                          <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${severityTone(alert.severity)}`}>
                            {alert.severity}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
          <div className="rounded-lg border border-white/10 bg-black/20 p-5">
            <div className="flex items-center gap-2">
              <TerminalSquare size={16} className="text-amber-300" />
              <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Tool Health</h3>
            </div>
            <div className="mt-4 space-y-2">
              {data?.toolsHealth.map((tool) => (
                <div key={tool.name} className="flex items-center justify-between rounded border border-white/10 bg-white/[0.03] px-3 py-2">
                  <span className="text-sm font-bold text-white">{tool.name}</span>
                  <span className={`rounded px-2 py-1 text-[10px] font-black uppercase tracking-wider ${
                    tool.status === 'available' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-slate-500/10 text-slate-400'
                  }`}>
                    {tool.status}
                  </span>
                </div>
              )) ?? <div className="text-sm text-slate-500">Loading tool health...</div>}
            </div>
          </div>

          <div className="rounded-lg border border-white/10 bg-black/20 p-5">
            <div className="flex items-center gap-2">
              <ShieldAlert size={16} className="text-red-300" />
              <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Open Alerts By Tool</h3>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {data && Object.entries(data.alertStats.open_by_tool).length > 0 ? (
                Object.entries(data.alertStats.open_by_tool).map(([tool, count]) => (
                  <button
                    key={tool}
                    onClick={() => onSelectModule(tool === 'sentinel' ? 'desktop_safety' : 'alerts')}
                    className="rounded border border-white/10 bg-white/[0.03] p-4 text-left transition-colors hover:bg-white/[0.06]"
                  >
                    <div className="text-[10px] font-black uppercase tracking-[0.25em] text-slate-500">{tool}</div>
                    <div className="mt-2 text-2xl font-black text-white">{count}</div>
                  </button>
                ))
              ) : (
                <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
                  No open alerts across tools.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
