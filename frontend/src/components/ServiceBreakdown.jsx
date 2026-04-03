import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6'];

const ServiceBreakdown = ({ data }) => {
  const chartData = Object.entries(data || {}).map(([name, value]) => ({ name, value }));

  return (
    <div className="bg-[#1e293b] rounded-xl p-6">
      <h3 className="text-lg font-semibold text-slate-300 mb-4">Findings by Service</h3>
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie data={chartData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
            dataKey="value" paddingAngle={4} strokeWidth={0}>
            {chartData.map((_, i) => (
              <Cell key={i} fill={COLORS[i % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' }}
          />
          <Legend
            formatter={(value) => <span style={{ color: '#94a3b8', fontSize: 12 }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ServiceBreakdown;
