import React, { startTransition, useEffect, useMemo, useState } from 'react';
import { Bug, FileWarning, Filter, Laptop } from 'lucide-react';
import { ApiVulnerability, SentinelVulnerabilityMatch } from '../types';
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

export const VulnerabilitiesWorkspace: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<ApiVulnerability[]>([]);
  const [sentinelMatches, setSentinelMatches] = useState<SentinelVulnerabilityMatch[]>([]);
  const [severity, setSeverity] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const load = async (showLoading = true) => {
      if (showLoading) setLoading(true);
      setError(null);
      try {
        const [nextVulns, nextSentinel] = await Promise.all([
          NetWatchApi.getVulnerabilities({ limit: 50, severity: severity === 'all' ? undefined : severity }),
          NetWatchApi.getSentinelVulns(50),
        ]);
        if (!active) return;
        startTransition(() => {
          setVulnerabilities(nextVulns);
          setSentinelMatches(nextSentinel.rows);
        });
      } catch (e: any) {
        if (!active) return;
        setError(e?.message || 'Failed to load vulnerabilities');
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
  }, [severity]);

  const criticalCount = useMemo(
    () => vulnerabilities.filter((item) => item.severity === 'critical').length + sentinelMatches.filter((item) => item.severity === 'CRITICAL').length,
    [vulnerabilities, sentinelMatches],
  );

  return (
    <div className="h-full overflow-y-auto bg-[#05070a]">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 p-6">
        <div className="rounded-lg border border-white/10 bg-black/20 p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="text-[11px] font-black uppercase tracking-[0.35em] text-amber-300">Vulnerabilities</div>
              <h2 className="mt-3 text-3xl font-black uppercase tracking-tight text-white">Exposure Across Network And Desktop</h2>
              <p className="mt-2 max-w-3xl text-sm text-slate-400">
                This workspace separates classic network-service vulnerabilities from Sentinel package exposure on the workstation, while keeping them in one triage surface.
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
              </select>
            </div>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          <div className="rounded border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-amber-300">Network Findings</div>
            <div className="mt-3 text-3xl font-black text-white">{vulnerabilities.length}</div>
          </div>
          <div className="rounded border border-cyan-500/20 bg-cyan-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-cyan-300">Desktop Package Matches</div>
            <div className="mt-3 text-3xl font-black text-white">{sentinelMatches.length}</div>
          </div>
          <div className="rounded border border-red-500/20 bg-red-500/5 p-4">
            <div className="text-[10px] font-black uppercase tracking-[0.25em] text-red-300">Critical Combined</div>
            <div className="mt-3 text-3xl font-black text-white">{criticalCount}</div>
          </div>
        </div>

        {loading ? (
          <div className="rounded border border-white/10 bg-black/20 p-4 text-sm text-slate-500">Loading vulnerability data...</div>
        ) : error ? (
          <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>
        ) : (
          <div className="grid gap-4 xl:grid-cols-2">
            <div className="rounded-lg border border-white/10 bg-black/20 p-5">
              <div className="flex items-center gap-2">
                <Bug size={16} className="text-amber-300" />
                <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Network / Service Vulnerabilities</h3>
              </div>
              <div className="mt-4 space-y-3">
                {vulnerabilities.length === 0 ? (
                  <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">No network vulnerability records match this filter.</div>
                ) : (
                  vulnerabilities.map((vuln) => (
                    <div key={vuln.id} className="rounded border border-white/10 bg-white/[0.03] p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-bold text-white">{vuln.title}</div>
                          <div className="mt-1 text-xs text-slate-500">{vuln.cve_id || 'No CVE ID'} · {vuln.source_tool}</div>
                          <div className="mt-2 text-sm text-slate-400">{vuln.description || 'No description provided.'}</div>
                          <div className="mt-3 flex flex-wrap gap-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                            {vuln.device_ip && <span>IP: {vuln.device_ip}</span>}
                            {vuln.service && <span>Service: {vuln.service}</span>}
                            {vuln.port ? <span>Port: {vuln.port}</span> : null}
                            <span>Status: {vuln.status}</span>
                          </div>
                        </div>
                        <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${severityTone(vuln.severity)}`}>
                          {vuln.severity}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="rounded-lg border border-white/10 bg-black/20 p-5">
              <div className="flex items-center gap-2">
                <Laptop size={16} className="text-cyan-300" />
                <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Desktop Package Exposure</h3>
              </div>
              <div className="mt-4 space-y-3">
                {sentinelMatches.length === 0 ? (
                  <div className="rounded border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">No Sentinel package matches in the current window.</div>
                ) : (
                  sentinelMatches.map((match) => (
                    <div key={match.id} className="rounded border border-white/10 bg-white/[0.03] p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <FileWarning size={14} className="text-amber-300" />
                            <div className="text-sm font-bold text-white">{match.package}</div>
                          </div>
                          <div className="mt-1 text-xs text-slate-500">{match.version} · {match.source}</div>
                          <div className="mt-3 flex flex-wrap gap-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                            <span>{match.cve_id}</span>
                            {match.exploited ? <span className="text-red-300">KEV</span> : null}
                            <span>{new Date(match.timestamp).toLocaleString()}</span>
                          </div>
                        </div>
                        <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase tracking-wider ${severityTone(match.severity)}`}>
                          {match.severity}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
