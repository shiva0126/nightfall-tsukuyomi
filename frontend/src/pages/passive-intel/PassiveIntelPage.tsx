import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Shield, Database, Globe, Server } from 'lucide-react';
import { API_URL } from '../../config';
import { IntelligencePanel } from '../../components/IntelligencePanel';

interface Scan {
  id: number;
  target_id: number;
  status: string;
  started_at: string;
}

export function PassiveIntelPage() {
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/scans`);
      return res.json();
    },
    refetchInterval: 3000,
  });

  const { data: targetsData } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/targets`);
      return res.json();
    },
  });

  const scans: Scan[] = scansData?.scans || [];
  const targets = targetsData?.targets || [];
  
  const completedScans = scans.filter(s => s.status === 'completed');

  const getTargetDomain = (targetId: number) => {
    const target = targets.find((t: any) => t.id === targetId);
    return target?.domain || 'Unknown';
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="w-8 h-8 text-indigo-500" strokeWidth={2} />
          <h1 className="text-2xl font-bold text-white">Passive Intelligence</h1>
        </div>
        <p className="text-sm text-slate-500">OSINT data gathered without direct target interaction</p>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Left: Scan List */}
        <div className="col-span-3">
          <div className="bg-[#1a1d29] rounded-lg p-4 border border-[#2a2d3a]">
            <div className="flex items-center gap-2 mb-4">
              <Database className="w-4 h-4 text-slate-500" />
              <h2 className="text-sm font-semibold text-white">Select Scan</h2>
            </div>
            <div className="space-y-2 max-h-[calc(100vh-280px)] overflow-y-auto pr-2">
              {completedScans.map((scan) => (
                <motion.button
                  key={scan.id}
                  onClick={() => setSelectedScanId(scan.id)}
                  whileHover={{ x: 2 }}
                  className={`w-full text-left p-3 rounded border transition-all ${
                    selectedScanId === scan.id
                      ? 'bg-indigo-600 border-indigo-500 text-white'
                      : 'bg-[#252836] border-[#2a2d3a] text-slate-400 hover:border-indigo-500/30'
                  }`}
                >
                  <div className="font-semibold text-sm mb-1">
                    Scan #{scan.id}
                  </div>
                  <div className="text-xs opacity-80 truncate">
                    {getTargetDomain(scan.target_id)}
                  </div>
                  <div className="text-[10px] opacity-60 mt-1">
                    {new Date(scan.started_at).toLocaleDateString()}
                  </div>
                </motion.button>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Intelligence Display */}
        <div className="col-span-9">
          {selectedScanId ? (
            <IntelligencePanel scanId={selectedScanId} />
          ) : (
            <div className="bg-[#1a1d29] rounded-lg p-16 border border-[#2a2d3a] text-center h-full flex flex-col items-center justify-center">
              <Shield className="w-16 h-16 text-slate-700 mb-4" strokeWidth={1.5} />
              <p className="text-lg font-semibold text-slate-400 mb-2">Select a Scan</p>
              <p className="text-sm text-slate-600">Choose a completed scan to view OSINT intelligence data</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
