import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, ChevronDown, ChevronUp, CheckCircle2, XCircle } from 'lucide-react';

const NistCompliance = ({ data }) => {
  const [expanded, setExpanded] = useState(true);

  if (!data) return null;

  const { controls, overall_compliance_pct } = data;

  const getBarColor = (pct) => {
    if (pct >= 80) return '#22c55e';
    if (pct >= 50) return '#eab308';
    return '#ef4444';
  };

  const sortedControls = [...(controls || [])].sort((a, b) => a.compliance_pct - b.compliance_pct);
  const failingControls = sortedControls.filter(c => c.failed > 0).length;
  const passingControls = sortedControls.filter(c => c.failed === 0).length;

  return (
    <div className="bg-[#1e293b] rounded-2xl border border-slate-700/50 overflow-hidden">
      {/* Header */}
      <div
        className="p-6 flex items-center justify-between cursor-pointer hover:bg-slate-800/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-4">
          <div className="p-2.5 rounded-lg"
            style={{ backgroundColor: (overall_compliance_pct >= 50 ? '#22c55e' : '#ef4444') + '15' }}>
            {overall_compliance_pct >= 50
              ? <ShieldCheck size={22} color="#22c55e" />
              : <ShieldAlert size={22} color="#ef4444" />
            }
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">NIST 800-53 Compliance</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {controls?.length || 0} controls assessed &middot;
              <span className="text-green-400"> {passingControls} passing</span> &middot;
              <span className="text-red-400"> {failingControls} failing</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className="text-3xl font-bold" style={{ color: getBarColor(overall_compliance_pct) }}>
              {overall_compliance_pct}%
            </span>
            <p className="text-xs text-slate-500">Overall</p>
          </div>
          {expanded ? <ChevronUp size={18} className="text-slate-500" /> : <ChevronDown size={18} className="text-slate-500" />}
        </div>
      </div>

      {/* Overall progress bar */}
      <div className="px-6 pb-4">
        <div className="w-full bg-slate-700/50 rounded-full h-2.5">
          <div
            className="h-2.5 rounded-full transition-all duration-700"
            style={{ width: `${overall_compliance_pct}%`, backgroundColor: getBarColor(overall_compliance_pct) }}
          />
        </div>
      </div>

      {/* Controls detail */}
      {expanded && (
        <div className="border-t border-slate-700/50">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-slate-700/20">
            {sortedControls.map((ctrl) => {
              const color = getBarColor(ctrl.compliance_pct);
              const isFullyCompliant = ctrl.failed === 0;
              return (
                <div key={ctrl.control_id} className="bg-[#1e293b] p-4 hover:bg-slate-800/30 transition-colors">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {isFullyCompliant
                        ? <CheckCircle2 size={14} className="text-green-500 shrink-0" />
                        : <XCircle size={14} className="text-red-500 shrink-0" />
                      }
                      <span className="font-mono text-xs text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                        {ctrl.control_id}
                      </span>
                      <span className="text-sm text-slate-300 truncate">{ctrl.name}</span>
                    </div>
                    <span className="text-xs font-bold ml-2 shrink-0" style={{ color }}>
                      {ctrl.compliance_pct}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-700/50 rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full transition-all duration-500"
                      style={{ width: `${Math.max(ctrl.compliance_pct, 2)}%`, backgroundColor: color }}
                    />
                  </div>
                  <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500">
                    <span className="text-green-500/70">{ctrl.passed} passed</span>
                    <span className="text-red-500/70">{ctrl.failed} failed</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default NistCompliance;
