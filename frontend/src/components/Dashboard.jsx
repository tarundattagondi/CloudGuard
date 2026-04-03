import React, { useEffect, useState, useCallback } from 'react';
import { Shield, RefreshCw, AlertTriangle, Activity, AlertOctagon, AlertCircle, Info } from 'lucide-react';
import { fetchSummary, fetchScanAll } from '../api/client';
import RiskScore from './RiskScore';
import SeverityChart from './SeverityChart';
import ServiceBreakdown from './ServiceBreakdown';
import NistCompliance from './NistCompliance';
import FindingsTable from './FindingsTable';

const StatCard = ({ label, value, icon: Icon, color, subtext }) => (
  <div className="bg-[#1e293b] rounded-xl p-5 border border-slate-700/50 hover:border-slate-600/50 transition-all duration-300 group">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-sm text-slate-400 mb-1">{label}</p>
        <p className="text-3xl font-bold tracking-tight" style={{ color }}>{value}</p>
        {subtext && <p className="text-xs text-slate-500 mt-1">{subtext}</p>}
      </div>
      <div className="p-2 rounded-lg transition-colors duration-300"
        style={{ backgroundColor: color + '15' }}>
        <Icon size={20} style={{ color }} />
      </div>
    </div>
  </div>
);

const Dashboard = () => {
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [lastScan, setLastScan] = useState(null);

  const loadData = useCallback(async (isRescan = false) => {
    if (isRescan) {
      setScanning(true);
    } else {
      setLoading(true);
    }
    setError(null);
    try {
      const [summaryData, scanData] = await Promise.all([fetchSummary(), fetchScanAll()]);
      setSummary(summaryData);
      setFindings(scanData.findings);
      setLastScan(new Date());
    } catch (err) {
      setError('Failed to connect to backend. Make sure the server is running on port 8000 with DEMO_MODE=true.');
    } finally {
      setLoading(false);
      setScanning(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0f172a] flex flex-col items-center justify-center gap-4">
        <div className="relative">
          <Shield className="text-blue-500/20" size={64} />
          <RefreshCw className="absolute inset-0 m-auto animate-spin text-blue-500" size={28} />
        </div>
        <div className="text-center">
          <p className="text-slate-300 font-medium">Scanning AWS Environment</p>
          <p className="text-slate-500 text-sm mt-1">Checking S3, IAM, Security Groups, CloudTrail, RDS...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-[#0f172a] flex items-center justify-center p-4">
        <div className="bg-[#1e293b] rounded-2xl p-8 max-w-md w-full text-center border border-slate-700/50">
          <div className="w-16 h-16 rounded-full bg-yellow-500/10 flex items-center justify-center mx-auto mb-4">
            <AlertTriangle className="text-yellow-500" size={32} />
          </div>
          <h2 className="text-lg font-semibold text-white mb-2">Connection Failed</h2>
          <p className="text-slate-400 text-sm mb-6">{error}</p>
          <div className="bg-slate-900/50 rounded-lg p-3 mb-6 text-left">
            <p className="text-xs text-slate-500 font-mono">
              cd backend<br />
              DEMO_MODE=true uvicorn main:app --reload
            </p>
          </div>
          <button onClick={() => loadData(false)}
            className="px-6 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors font-medium text-sm">
            Try Again
          </button>
        </div>
      </div>
    );
  }

  const medLow = (summary?.findings_by_severity?.MEDIUM || 0) + (summary?.findings_by_severity?.LOW || 0);

  return (
    <div className="min-h-screen bg-[#0f172a]">
      {/* Header */}
      <header className="border-b border-slate-800/80 bg-[#0f172a]/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600/10 rounded-lg">
              <Shield className="text-blue-500" size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold text-white tracking-tight">CloudGuard</h1>
                <span className="text-[10px] bg-blue-500/15 text-blue-400 px-2 py-0.5 rounded-full font-medium uppercase tracking-wider">
                  Demo
                </span>
              </div>
              <p className="text-xs text-slate-500">AWS Security Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {lastScan && (
              <span className="text-xs text-slate-500 hidden sm:block">
                Last scan: {lastScan.toLocaleTimeString()}
              </span>
            )}
            <button onClick={() => loadData(true)} disabled={scanning}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-all text-sm font-medium">
              <RefreshCw size={14} className={scanning ? 'animate-spin' : ''} />
              {scanning ? 'Scanning...' : 'Scan Now'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Scanning overlay */}
        {scanning && (
          <div className="fixed inset-0 bg-[#0f172a]/60 backdrop-blur-sm z-40 flex items-center justify-center">
            <div className="bg-[#1e293b] rounded-2xl p-8 text-center border border-slate-700/50">
              <RefreshCw className="animate-spin text-blue-500 mx-auto mb-4" size={36} />
              <p className="text-white font-medium">Running Security Scan...</p>
              <p className="text-slate-400 text-sm mt-1">Checking all AWS services</p>
            </div>
          </div>
        )}

        {/* Stat Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Total Findings"
            value={summary?.total_findings || 0}
            icon={Activity}
            color="#f8fafc"
            subtext="Failed checks across all services"
          />
          <StatCard
            label="Critical"
            value={summary?.findings_by_severity?.CRITICAL || 0}
            icon={AlertOctagon}
            color="#ef4444"
            subtext="Require immediate attention"
          />
          <StatCard
            label="High"
            value={summary?.findings_by_severity?.HIGH || 0}
            icon={AlertCircle}
            color="#f97316"
            subtext="Should be addressed soon"
          />
          <StatCard
            label="Medium + Low"
            value={medLow}
            icon={Info}
            color="#eab308"
            subtext="Monitor and plan remediation"
          />
        </div>

        {/* Risk Score + Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <RiskScore score={summary?.overall_risk_score || 0} />
          <SeverityChart data={summary?.findings_by_severity} />
          <ServiceBreakdown data={summary?.findings_by_service} />
        </div>

        {/* NIST Compliance */}
        <NistCompliance data={summary?.nist_compliance} />

        {/* Findings Table */}
        <FindingsTable findings={findings} />

        {/* Footer */}
        <footer className="text-center py-4 border-t border-slate-800/50">
          <p className="text-xs text-slate-600">
            CloudGuard Security Scanner &middot; NIST 800-53 Compliance Mapping &middot; Demo Mode
          </p>
        </footer>
      </main>
    </div>
  );
};

export default Dashboard;
