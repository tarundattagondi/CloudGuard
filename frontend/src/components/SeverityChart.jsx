import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0].payload;
  return (
    <div className="bg-[#0f172a] border border-slate-700 rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs text-slate-400">{name}</p>
      <p className="text-sm font-bold" style={{ color: COLORS[name] }}>{value} findings</p>
    </div>
  );
};

const SeverityChart = ({ data }) => {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const chartData = order.map(name => ({ name, value: data?.[name] || 0 }));

  return (
    <div className="bg-[#1e293b] rounded-2xl p-6 border border-slate-700/50">
      <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-6">By Severity</h3>
      <ResponsiveContainer width="100%" height={210}>
        <BarChart data={chartData} barSize={36}>
          <XAxis
            dataKey="name" axisLine={false} tickLine={false}
            tick={{ fill: '#64748b', fontSize: 11, fontWeight: 500 }}
          />
          <YAxis
            axisLine={false} tickLine={false} allowDecimals={false}
            tick={{ fill: '#475569', fontSize: 11 }} width={24}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(148,163,184,0.05)' }} />
          <Bar dataKey="value" radius={[8, 8, 0, 0]}>
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SeverityChart;
