import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const SERVICE_COLORS = {
  S3: '#ef4444',
  IAM: '#f97316',
  EC2: '#eab308',
  CloudTrail: '#3b82f6',
  RDS: '#8b5cf6',
};

const FALLBACK_COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#ec4899'];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0].payload;
  return (
    <div className="bg-[#0f172a] border border-slate-700 rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs text-slate-400">{name}</p>
      <p className="text-sm font-bold text-white">{value} findings</p>
    </div>
  );
};

const ServiceBreakdown = ({ data }) => {
  const chartData = Object.entries(data || {}).map(([name, value]) => ({ name, value }));
  const total = chartData.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="bg-[#1e293b] rounded-2xl p-6 border border-slate-700/50">
      <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">By Service</h3>
      <div className="flex items-center gap-4">
        <div className="w-1/2">
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={chartData} cx="50%" cy="50%" innerRadius={48} outerRadius={72}
                dataKey="value" paddingAngle={3} strokeWidth={0}>
                {chartData.map((entry, i) => (
                  <Cell key={entry.name} fill={SERVICE_COLORS[entry.name] || FALLBACK_COLORS[i % FALLBACK_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="w-1/2 space-y-2.5">
          {chartData.map((entry, i) => {
            const color = SERVICE_COLORS[entry.name] || FALLBACK_COLORS[i % FALLBACK_COLORS.length];
            const pct = total > 0 ? Math.round((entry.value / total) * 100) : 0;
            return (
              <div key={entry.name} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
                  <span className="text-xs text-slate-300">{entry.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-200">{entry.value}</span>
                  <span className="text-[10px] text-slate-500 w-8 text-right">{pct}%</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ServiceBreakdown;
