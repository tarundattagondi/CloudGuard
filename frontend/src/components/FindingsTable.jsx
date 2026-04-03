import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronRight, Search, Filter, Terminal } from 'lucide-react';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', dot: '#ef4444' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)', text: '#f97316', dot: '#f97316' },
  MEDIUM:   { bg: 'rgba(234,179,8,0.15)',  text: '#eab308', dot: '#eab308' },
  LOW:      { bg: 'rgba(34,197,94,0.15)',   text: '#22c55e', dot: '#22c55e' },
};

const STATUS_STYLES = {
  PASS: { bg: 'rgba(59,130,246,0.15)', text: '#3b82f6' },
  FAIL: { bg: 'rgba(239,68,68,0.15)', text: '#ef4444' },
};

const FindingsTable = ({ findings }) => {
  const [expandedId, setExpandedId] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [filterService, setFilterService] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const services = useMemo(() => [...new Set((findings || []).map(f => f.service))].sort(), [findings]);

  const filtered = useMemo(() => {
    let result = findings || [];

    if (filterSeverity !== 'ALL') result = result.filter(f => f.severity === filterSeverity);
    if (filterStatus !== 'ALL') result = result.filter(f => f.status === filterStatus);
    if (filterService !== 'ALL') result = result.filter(f => f.service === filterService);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(f =>
        f.check_name.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.nist_control.toLowerCase().includes(q)
      );
    }

    return [...result].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [findings, filterSeverity, filterStatus, filterService, searchQuery]);

  const failCount = filtered.filter(f => f.status === 'FAIL').length;
  const passCount = filtered.filter(f => f.status === 'PASS').length;

  return (
    <div className="bg-[#1e293b] rounded-2xl border border-slate-700/50 overflow-hidden">
      {/* Header */}
      <div className="p-6 border-b border-slate-700/50">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Security Findings</h3>
            <p className="text-sm text-slate-400 mt-0.5">
              {filtered.length} results &middot;
              <span className="text-red-400"> {failCount} failed</span> &middot;
              <span className="text-blue-400"> {passCount} passed</span>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="bg-slate-800 text-slate-300 text-sm rounded-lg pl-9 pr-3 py-2 border border-slate-600/50 outline-none focus:border-blue-500/50 transition-colors w-48"
              />
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2 mt-4">
          <Filter size={14} className="text-slate-500" />
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
            className="bg-slate-800 text-slate-300 text-xs rounded-lg px-3 py-1.5 border border-slate-600/50 outline-none focus:border-blue-500/50 cursor-pointer">
            <option value="ALL">All Status</option>
            <option value="FAIL">Failed Only</option>
            <option value="PASS">Passed Only</option>
          </select>
          <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}
            className="bg-slate-800 text-slate-300 text-xs rounded-lg px-3 py-1.5 border border-slate-600/50 outline-none focus:border-blue-500/50 cursor-pointer">
            <option value="ALL">All Severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={filterService} onChange={e => setFilterService(e.target.value)}
            className="bg-slate-800 text-slate-300 text-xs rounded-lg px-3 py-1.5 border border-slate-600/50 outline-none focus:border-blue-500/50 cursor-pointer">
            <option value="ALL">All Services</option>
            {services.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          {(filterStatus !== 'ALL' || filterSeverity !== 'ALL' || filterService !== 'ALL' || searchQuery) && (
            <button
              onClick={() => { setFilterStatus('ALL'); setFilterSeverity('ALL'); setFilterService('ALL'); setSearchQuery(''); }}
              className="text-xs text-blue-400 hover:text-blue-300 transition-colors ml-1"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead>
            <tr className="text-xs uppercase text-slate-500 bg-slate-800/50 tracking-wider">
              <th className="py-3 px-4 w-10"></th>
              <th className="py-3 px-4">Service</th>
              <th className="py-3 px-4">Check Name</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">NIST Control</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/30">
            {filtered.map((f) => {
              const isExpanded = expandedId === f.id;
              const sevStyle = SEVERITY_COLORS[f.severity];
              const statStyle = STATUS_STYLES[f.status];
              return (
                <React.Fragment key={f.id}>
                  <tr
                    className={`cursor-pointer transition-colors duration-150 ${isExpanded ? 'bg-slate-800/60' : 'hover:bg-slate-800/30'}`}
                    onClick={() => setExpandedId(isExpanded ? null : f.id)}
                  >
                    <td className="py-3.5 px-4 text-slate-500">
                      {isExpanded
                        ? <ChevronDown size={16} className="text-blue-400" />
                        : <ChevronRight size={16} />
                      }
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="text-slate-200 font-medium">{f.service}</span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 max-w-xs truncate">{f.check_name}</td>
                    <td className="py-3.5 px-4">
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold"
                        style={{ backgroundColor: sevStyle.bg, color: sevStyle.text }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: sevStyle.dot }} />
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold"
                        style={{ backgroundColor: statStyle.bg, color: statStyle.text }}>
                        {f.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono text-xs text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                        {f.nist_control}
                      </span>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="bg-slate-900/40">
                      <td colSpan={6} className="px-4 py-0">
                        <div className="py-5 pl-10 pr-4 space-y-4 border-l-2 ml-3"
                          style={{ borderColor: sevStyle.dot + '40' }}>
                          <div>
                            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5">Description</p>
                            <p className="text-sm text-slate-300 leading-relaxed">{f.description}</p>
                          </div>
                          <div>
                            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                              <Terminal size={12} />
                              Remediation
                            </p>
                            <div className="bg-slate-950/60 border border-slate-700/30 rounded-lg p-3">
                              <p className="text-sm text-emerald-400/90 font-mono leading-relaxed break-all">{f.remediation}</p>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500">
                  No findings match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default FindingsTable;
