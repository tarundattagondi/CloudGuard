import React, { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const STATUS_COLORS = {
  PASS: '#3b82f6',
  FAIL: '#ef4444',
};

const FindingsTable = ({ findings }) => {
  const [expandedId, setExpandedId] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [filterService, setFilterService] = useState('ALL');

  const filtered = (findings || []).filter((f) => {
    if (filterSeverity !== 'ALL' && f.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && f.status !== filterStatus) return false;
    if (filterService !== 'ALL' && f.service !== filterService) return false;
    return true;
  });

  const services = [...new Set((findings || []).map(f => f.service))];

  return (
    <div className="bg-[#1e293b] rounded-xl p-6">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <h3 className="text-lg font-semibold text-slate-300">
          All Findings <span className="text-sm text-slate-500">({filtered.length})</span>
        </h3>
        <div className="flex gap-2">
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
            className="bg-slate-700 text-slate-300 text-sm rounded-lg px-3 py-1.5 border-none outline-none">
            <option value="ALL">All Status</option>
            <option value="FAIL">FAIL</option>
            <option value="PASS">PASS</option>
          </select>
          <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}
            className="bg-slate-700 text-slate-300 text-sm rounded-lg px-3 py-1.5 border-none outline-none">
            <option value="ALL">All Severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={filterService} onChange={e => setFilterService(e.target.value)}
            className="bg-slate-700 text-slate-300 text-sm rounded-lg px-3 py-1.5 border-none outline-none">
            <option value="ALL">All Services</option>
            {services.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead>
            <tr className="text-slate-400 border-b border-slate-700">
              <th className="py-3 px-2 w-8"></th>
              <th className="py-3 px-2">Service</th>
              <th className="py-3 px-2">Check</th>
              <th className="py-3 px-2">Status</th>
              <th className="py-3 px-2">Severity</th>
              <th className="py-3 px-2">NIST</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <React.Fragment key={f.id}>
                <tr
                  className="border-b border-slate-700/50 hover:bg-slate-700/30 cursor-pointer"
                  onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                >
                  <td className="py-3 px-2 text-slate-400">
                    {expandedId === f.id ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </td>
                  <td className="py-3 px-2 text-slate-300 font-medium">{f.service}</td>
                  <td className="py-3 px-2 text-slate-300">{f.check_name}</td>
                  <td className="py-3 px-2">
                    <span className="px-2 py-0.5 rounded text-xs font-bold"
                      style={{ backgroundColor: STATUS_COLORS[f.status] + '20', color: STATUS_COLORS[f.status] }}>
                      {f.status}
                    </span>
                  </td>
                  <td className="py-3 px-2">
                    <span className="px-2 py-0.5 rounded text-xs font-bold"
                      style={{ backgroundColor: SEVERITY_COLORS[f.severity] + '20', color: SEVERITY_COLORS[f.severity] }}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="py-3 px-2 text-slate-400 font-mono text-xs">{f.nist_control}</td>
                </tr>
                {expandedId === f.id && (
                  <tr className="bg-slate-800/50">
                    <td colSpan={6} className="px-6 py-4">
                      <div className="space-y-2">
                        <div>
                          <span className="text-slate-400 text-xs font-semibold uppercase">Description</span>
                          <p className="text-slate-300 text-sm mt-1">{f.description}</p>
                        </div>
                        <div>
                          <span className="text-slate-400 text-xs font-semibold uppercase">Remediation</span>
                          <p className="text-slate-300 text-sm mt-1 font-mono bg-slate-900/50 p-2 rounded">{f.remediation}</p>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default FindingsTable;
