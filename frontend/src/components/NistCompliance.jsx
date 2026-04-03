import React from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';

const NistCompliance = ({ data }) => {
  if (!data) return null;

  const { controls, overall_compliance_pct } = data;

  const getBarColor = (pct) => {
    if (pct >= 80) return '#22c55e';
    if (pct >= 50) return '#eab308';
    return '#ef4444';
  };

  return (
    <div className="bg-[#1e293b] rounded-xl p-6">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-slate-300">NIST 800-53 Compliance</h3>
        <div className="flex items-center gap-2">
          {overall_compliance_pct >= 50 ? (
            <ShieldCheck size={20} color="#22c55e" />
          ) : (
            <ShieldAlert size={20} color="#ef4444" />
          )}
          <span className="text-2xl font-bold" style={{ color: getBarColor(overall_compliance_pct) }}>
            {overall_compliance_pct}%
          </span>
        </div>
      </div>
      <div className="space-y-3 max-h-80 overflow-y-auto pr-2">
        {(controls || []).map((ctrl) => (
          <div key={ctrl.control_id} className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-400 w-12 shrink-0">{ctrl.control_id}</span>
            <div className="flex-1 min-w-0">
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 truncate">{ctrl.name}</span>
                <span className="text-slate-400 shrink-0 ml-2">
                  {ctrl.passed}P / {ctrl.failed}F
                </span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className="h-2 rounded-full transition-all duration-500"
                  style={{ width: `${ctrl.compliance_pct}%`, backgroundColor: getBarColor(ctrl.compliance_pct) }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default NistCompliance;
