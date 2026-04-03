import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const SeverityChart = ({ data }) => {
  const chartData = Object.entries(data || {}).map(([name, value]) => ({ name, value }));
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  chartData.sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name));

  return (
    <div className="bg-[#1e293b] rounded-xl p-6">
      <h3 className="text-lg font-semibold text-slate-300 mb-4">Findings by Severity</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} barSize={40}>
          <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' }}
          />
          <Bar dataKey="value" radius={[6, 6, 0, 0]}>
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] || '#64748b'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SeverityChart;
