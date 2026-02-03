import { motion } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import { Bell, Settings, User } from 'lucide-react';
import { API_URL } from '../../config';

export function TopBar() {
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/scans`);
      return res.json();
    },
    refetchInterval: 3000,
  });

  const scans = scansData?.scans || [];
  const activeScans = scans.filter((s: any) => 
    s.status === 'running' || s.status === 'passive_recon'
  ).length;

  return (
    <div className="h-14 bg-[#1a1d29] border-b border-[#2a2d3a] flex items-center justify-between px-6">
      {/* Left: Status */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-3">
          {activeScans > 0 ? (
            <>
              <div className="relative">
                <motion.div
                  animate={{ scale: [1, 1.2, 1] }}
                  transition={{ repeat: Infinity, duration: 2 }}
                  className="w-2 h-2 bg-green-500 rounded-full"
                />
                <motion.div
                  animate={{ scale: [1, 1.6, 1], opacity: [0.6, 0, 0.6] }}
                  transition={{ repeat: Infinity, duration: 2 }}
                  className="absolute inset-0 w-2 h-2 bg-green-500 rounded-full"
                />
              </div>
              <div className="flex flex-col">
                <span className="text-xs font-semibold text-green-500">
                  {activeScans} Active Scan{activeScans > 1 ? 's' : ''}
                </span>
                <span className="text-[10px] text-slate-600">Running</span>
              </div>
            </>
          ) : (
            <>
              <div className="w-2 h-2 bg-slate-700 rounded-full" />
              <div className="flex flex-col">
                <span className="text-xs font-semibold text-slate-500">Idle</span>
                <span className="text-[10px] text-slate-700">No active scans</span>
              </div>
            </>
          )}
        </div>

        <div className="h-8 w-px bg-[#2a2d3a]" />

        <div className="flex items-center gap-2">
          <span className="text-[10px] text-slate-600 font-semibold uppercase tracking-wider">
            Total Scans
          </span>
          <span className="text-sm font-semibold text-white bg-[#252836] px-2 py-0.5 rounded">
            {scans.length}
          </span>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-1">
        {/* Notifications */}
        <button className="relative p-2 hover:bg-[#252836] rounded transition-colors">
          <Bell className="w-[18px] h-[18px] text-slate-500" strokeWidth={2} />
          {activeScans > 0 && (
            <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-red-500 rounded-full" />
          )}
        </button>

        {/* Settings */}
        <button className="p-2 hover:bg-[#252836] rounded transition-colors">
          <Settings className="w-[18px] h-[18px] text-slate-500" strokeWidth={2} />
        </button>

        <div className="h-8 w-px bg-[#2a2d3a] mx-2" />

        {/* User */}
        <button className="flex items-center gap-2 px-2 py-1.5 hover:bg-[#252836] rounded transition-colors">
          <div className="w-7 h-7 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full flex items-center justify-center">
            <User className="w-4 h-4 text-white" strokeWidth={2.5} />
          </div>
          <div className="flex flex-col items-start">
            <span className="text-xs font-semibold text-white">Admin</span>
            <span className="text-[10px] text-slate-600">Security Analyst</span>
          </div>
        </button>
      </div>
    </div>
  );
}
