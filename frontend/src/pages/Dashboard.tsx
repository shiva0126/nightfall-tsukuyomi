import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Shield, Activity, Target, AlertTriangle, Cpu, Globe } from 'lucide-react';
import RiskGauge from '../components/RiskGauge';
import StatCard from '../components/StatCard';
import ScanButton from '../components/ScanButton';
import { scanAPI, targetAPI } from '../lib/api';
import { useState } from 'react';

export default function Dashboard() {
  const [selectedTarget, setSelectedTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await scanAPI.list();
      return response.data;
    },
    refetchInterval: 5000, // Auto-refresh every 5 seconds
  });

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const response = await targetAPI.list();
      return response.data;
    },
  });

  const handleScan = async () => {
    if (!selectedTarget) return;
    setIsScanning(true);
    try {
      await scanAPI.create({ domain: selectedTarget });
      setTimeout(() => setIsScanning(false), 3000);
    } catch (error) {
      console.error('Scan failed:', error);
      setIsScanning(false);
    }
  };

  const latestScan = scans?.scans?.[0];
  const riskScore = latestScan?.risk_score || 0;

  return (
    <div className="min-h-screen p-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-12"
      >
        <div className="flex items-center gap-4 mb-4">
          <div className="relative">
            <div className="absolute inset-0 bg-cyber-purple/50 blur-xl rounded-full animate-pulse" />
            <Shield className="w-12 h-12 text-cyber-cyan relative z-10" />
          </div>
          <div>
            <h1 className="text-5xl font-black bg-gradient-to-r from-cyber-purple via-cyber-cyan to-cyber-pink text-transparent bg-clip-text">
              NIGHTFALL TSUKUYOMI
            </h1>
            <p className="text-gray-400 text-sm mt-1">Advanced Security Intelligence Platform</p>
          </div>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <StatCard
            title="Total Scans"
            value={scans?.count || 0}
            icon={Activity}
            trend="12%"
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <StatCard
            title="Active Targets"
            value={targets?.count || 0}
            icon={Target}
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <StatCard
            title="Critical Findings"
            value={0}
            icon={AlertTriangle}
            color="cyber-pink"
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <StatCard
            title="System Status"
            value="ONLINE"
            icon={Cpu}
            color="cyber-cyan"
          />
        </motion.div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left: Risk Gauge */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="glass-card p-8 flex flex-col items-center justify-center"
        >
          <h2 className="text-2xl font-bold text-white mb-6">RISK ANALYSIS</h2>
          <RiskGauge score={riskScore} />
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-400">Last Updated</p>
            <p className="text-white font-semibold">
              {latestScan?.started_at ? new Date(latestScan.started_at).toLocaleString() : 'Never'}
            </p>
          </div>
        </motion.div>

        {/* Center: Scan Control */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-8"
        >
          <div className="flex items-center gap-3 mb-6">
            <Globe className="w-6 h-6 text-cyber-cyan" />
            <h2 className="text-2xl font-bold text-white">SCAN TARGET</h2>
          </div>

          <div className="space-y-6">
            <div>
              <label className="block text-sm text-gray-400 mb-2">Target Domain</label>
              <input
                type="text"
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                placeholder="example.com"
                className="w-full px-4 py-3 bg-white/5 border border-cyber-purple/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyber-cyan transition-colors"
              />
            </div>

            <ScanButton onClick={handleScan} loading={isScanning} />

            {/* Recent Targets */}
            <div className="mt-8">
              <h3 className="text-sm text-gray-400 mb-3 uppercase tracking-wider">Recent Targets</h3>
              <div className="space-y-2">
                {targets?.targets?.slice(0, 3).map((target: any) => (
                  <motion.button
                    key={target.id}
                    whileHover={{ x: 5 }}
                    onClick={() => setSelectedTarget(target.domain)}
                    className="w-full text-left px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white transition-colors"
                  >
                    {target.domain}
                  </motion.button>
                ))}
              </div>
            </div>
          </div>
        </motion.div>

        {/* Right: Live Feed */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="glass-card p-8"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="relative">
              <div className="absolute inset-0 bg-green-500/50 blur-md rounded-full animate-pulse" />
              <div className="w-3 h-3 bg-green-500 rounded-full relative z-10" />
            </div>
            <h2 className="text-2xl font-bold text-white">LIVE FEED</h2>
          </div>

          <div className="space-y-3 h-96 overflow-y-auto">
            {scans?.scans?.map((scan: any, idx: number) => (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.1 }}
                className="p-4 bg-white/5 border border-white/10 rounded-lg"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className={`px-2 py-1 text-xs font-bold rounded ${
                    scan.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                    scan.status === 'pending' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-blue-500/20 text-blue-400'
                  }`}>
                    {scan.status.toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-400">
                    Scan #{scan.id}
                  </span>
                </div>
                <p className="text-sm text-white">Target ID: {scan.target_id}</p>
                <p className="text-xs text-gray-400 mt-1">
                  {new Date(scan.started_at).toLocaleString()}
                </p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
