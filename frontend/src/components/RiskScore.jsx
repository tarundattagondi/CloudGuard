import React from 'react';
import { TrendingDown, TrendingUp } from 'lucide-react';

const RiskScore = ({ score }) => {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const getColor = () => {
    if (score >= 80) return '#22c55e';
    if (score >= 60) return '#eab308';
    if (score >= 40) return '#f97316';
    return '#ef4444';
  };

  const getLabel = () => {
    if (score >= 80) return 'Low Risk';
    if (score >= 60) return 'Moderate';
    if (score >= 40) return 'High Risk';
    return 'Critical Risk';
  };

  const color = getColor();

  return (
    <div className="bg-[#1e293b] rounded-2xl p-6 border border-slate-700/50 flex flex-col items-center justify-center">
      <div className="flex items-center justify-between w-full mb-4">
        <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Risk Score</h3>
        {score >= 50
          ? <TrendingUp size={16} className="text-green-500" />
          : <TrendingDown size={16} className="text-red-500" />
        }
      </div>
      <div className="relative w-40 h-40">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 160 160">
          <circle cx="80" cy="80" r={radius} fill="none" stroke="#1e293b" strokeWidth="14" />
          <circle cx="80" cy="80" r={radius} fill="none" stroke="#334155" strokeWidth="14"
            strokeDasharray="4 4" />
          <circle
            cx="80" cy="80" r={radius} fill="none"
            stroke={color} strokeWidth="14"
            strokeDasharray={circumference} strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-5xl font-black tabular-nums" style={{ color }}>{score}</span>
          <span className="text-xs text-slate-500 mt-0.5">out of 100</span>
        </div>
      </div>
      <div className="mt-4 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
        <span className="text-sm font-medium" style={{ color }}>{getLabel()}</span>
      </div>
    </div>
  );
};

export default RiskScore;
