import React, { useEffect, useState } from 'react';
import { Shield, RefreshCw, AlertTriangle } from 'lucide-react';
import { fetchSummary, fetchScanAll } from '../api/client';
import RiskScore from './RiskScore';
import SeverityChart from './SeverityChart';
import ServiceBreakdown from './ServiceBreakdown';
import NistCompliance from './NistCompliance';
import FindingsTable from './FindingsTable';

const Dashboard = () => {
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [summaryData, scanData] = await Promise.all([fetchSummary(), fetchScanAll()]);
      setSummary(summaryData);
      setFindings(scanData.findings);
    } catch (err) {
      setError('Failed to connect to backend. Make sure the server is running on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0f172a] flex items-center justify-center">
        <RefreshCw className="animate-spin text-blue-500" size={32} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-[#0f172a] flex items-center justify-center">
        <div className="bg-[#1e293b] rounded-xl p-8 max-w-md text-center">
          <AlertTriangle className="mx-auto mb-4 text-yellow-500" size={40} />
          <p className="text-slate-300">{error}</p>
          <button onClick={loadData}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f172a]">
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="text-blue-500" size={28} />
            <h1 className="text-xl font-bold text-white">CloudGuard</h1>
            <span className="text-xs bg-blue-600/20 text-blue-400 px-2 py-0.5 rounded-full">DEMO MODE</span>
          </div>
          <button onClick={loadData}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition text-sm">
            <RefreshCw size={14} />
            Re-scan
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* Stats row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-[#1e293b] rounded-xl p-4">
            <p className="text-sm text-slate-400">Total Findings</p>
            <p className="text-3xl font-bold text-white">{summary?.total_findings}</p>
          </div>
          <div className="bg-[#1e293b] rounded-xl p-4">
            <p className="text-sm text-slate-400">Critical</p>
            <p className="text-3xl font-bold text-[#ef4444]">{summary?.findings_by_severity?.CRITICAL || 0}</p>
          </div>
          <div className="bg-[#1e293b] rounded-xl p-4">
            <p className="text-sm text-slate-400">High</p>
            <p className="text-3xl font-bold text-[#f97316]">{summary?.findings_by_severity?.HIGH || 0}</p>
          </div>
          <div className="bg-[#1e293b] rounded-xl p-4">
            <p className="text-sm text-slate-400">Compliance</p>
            <p className="text-3xl font-bold text-[#3b82f6]">{summary?.nist_compliance?.overall_compliance_pct || 0}%</p>
          </div>
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <RiskScore score={summary?.overall_risk_score || 0} />
          <SeverityChart data={summary?.findings_by_severity} />
          <ServiceBreakdown data={summary?.findings_by_service} />
        </div>

        {/* NIST Compliance */}
        <NistCompliance data={summary?.nist_compliance} />

        {/* Findings Table */}
        <FindingsTable findings={findings} />
      </main>
    </div>
  );
};

export default Dashboard;
