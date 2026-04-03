import React from 'react';

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
    return 'Critical';
  };

  return (
    <div className="bg-[#1e293b] rounded-xl p-6 flex flex-col items-center">
      <h3 className="text-lg font-semibold text-slate-300 mb-4">Risk Score</h3>
      <div className="relative w-44 h-44">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 160 160">
          <circle cx="80" cy="80" r={radius} fill="none" stroke="#334155" strokeWidth="12" />
          <circle
            cx="80" cy="80" r={radius} fill="none"
            stroke={getColor()} strokeWidth="12"
            strokeDasharray={circumference} strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-1000"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold" style={{ color: getColor() }}>{score}</span>
          <span className="text-sm text-slate-400">/100</span>
        </div>
      </div>
      <span className="mt-3 text-sm font-medium px-3 py-1 rounded-full"
        style={{ backgroundColor: getColor() + '20', color: getColor() }}>
        {getLabel()}
      </span>
    </div>
  );
};

export default RiskScore;
