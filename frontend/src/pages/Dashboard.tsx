import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { LayoutDashboard, Activity, AlertTriangle, Shield, TrendingUp } from 'lucide-react';
import { ScanButton } from '../components/ScanButton';
import { API_URL } from '../config';

interface Scan {
  id: number;
  status: string;
  risk_score: number;
  started_at: string;
}

interface Finding {
  id: number;
  severity: string;
  category: string;
}

export function Dashboard() {
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/scans`);
      return res.json();
    },
    refetchInterval: 3000,
  });

  const scans: Scan[] = scansData?.scans || [];
  const latestScan = scans[0];
  
  const totalScans = scans.length;
  const activeScans = scans.filter(s => s.status === 'running' || s.status === 'passive_recon').length;
  const avgRisk = scans.length > 0 ? Math.round(scans.reduce((acc, s) => acc + s.risk_score, 0) / scans.length) : 0;

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <LayoutDashboard className="w-8 h-8 text-indigo-500" strokeWidth={2} />
            <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          </div>
          <p className="text-sm text-slate-500">Security intelligence overview and metrics</p>
        </div>
        <ScanButton />
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-6 mb-8">
        {/* Total Scans */}
        <motion.div
          whileHover={{ y: -2 }}
          className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]"
        >
          <div className="flex items-center justify-between mb-4">
            <Activity className="w-5 h-5 text-indigo-500" strokeWidth={2} />
            <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Total Scans</span>
          </div>
          <div className="text-3xl font-bold text-white mb-1">{totalScans}</div>
          <div className="text-xs text-slate-500">
            {activeScans > 0 ? `${activeScans} active` : 'All complete'}
          </div>
        </motion.div>

        {/* Active Scans */}
        <motion.div
          whileHover={{ y: -2 }}
          className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]"
        >
          <div className="flex items-center justify-between mb-4">
            <Shield className="w-5 h-5 text-green-500" strokeWidth={2} />
            <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Active Scans</span>
          </div>
          <div className="text-3xl font-bold text-white mb-1">{activeScans}</div>
          <div className="text-xs text-slate-500">Running now</div>
        </motion.div>

        {/* Average Risk */}
        <motion.div
          whileHover={{ y: -2 }}
          className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]"
        >
          <div className="flex items-center justify-between mb-4">
            <AlertTriangle className="w-5 h-5 text-yellow-500" strokeWidth={2} />
            <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Avg Risk</span>
          </div>
          <div className="text-3xl font-bold text-white mb-1">{avgRisk}/100</div>
          <div className={`text-xs ${
            avgRisk >= 70 ? 'text-red-500' : avgRisk >= 40 ? 'text-yellow-500' : 'text-green-500'
          }`}>
            {avgRisk >= 70 ? 'High' : avgRisk >= 40 ? 'Medium' : 'Low'} severity
          </div>
        </motion.div>

        {/* Latest Risk */}
        <motion.div
          whileHover={{ y: -2 }}
          className="bg-[#1a1d29] rounded-lg p-6 border border-[#2a2d3a]"
        >
          <div className="flex items-center justify-between mb-4">
            <TrendingUp className="w-5 h-5 text-purple-500" strokeWidth={2} />
            <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Latest Risk</span>
          </div>
          <div className="text-3xl font-bold text-white mb-1">
            {latestScan?.risk_score || 0}/100
          </div>
          <div className="text-xs text-slate-500">{latestScan?.status || 'No scans'}</div>
        </motion.div>
      </div>

      {/* Recent Activity */}
      <div className="bg-[#1a1d29] rounded-lg border border-[#2a2d3a] p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>
        <div className="space-y-3">
          {scans.slice(0, 5).map((scan) => (
            <div
              key={scan.id}
              className="flex items-center justify-between p-3 bg-[#252836] rounded border border-[#2a2d3a] hover:border-indigo-500/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-indigo-500" />
                <div>
                  <div className="text-sm font-semibold text-white">Scan #{scan.id}</div>
                  <div className="text-xs text-slate-500">
                    {new Date(scan.started_at).toLocaleString()}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className={`px-2 py-1 rounded text-xs font-medium ${
                  scan.status === 'completed' ? 'bg-green-500/10 text-green-500' :
                  scan.status === 'running' || scan.status === 'passive_recon' ? 'bg-yellow-500/10 text-yellow-500' :
                  'bg-slate-500/10 text-slate-500'
                }`}>
                  {scan.status}
                </span>
                <span className={`text-sm font-semibold ${
                  scan.risk_score >= 70 ? 'text-red-500' :
                  scan.risk_score >= 40 ? 'text-yellow-500' :
                  'text-green-500'
                }`}>
                  {scan.risk_score}/100
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
