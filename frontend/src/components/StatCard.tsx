import { motion } from 'framer-motion';

interface StatCardProps {
  title: string;
  value: number | string;
  trend: string;
  icon: string;
}

export default function StatCard({ title, value, trend, icon }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ scale: 1.05 }}
      className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-xl p-6 border border-purple-500/20 backdrop-blur-sm"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-2xl">{icon}</span>
        <span className="text-slate-400 text-sm">{title}</span>
      </div>
      <div className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400">
        {value}
      </div>
      <div className="text-xs text-slate-500 mt-1">{trend}</div>
    </motion.div>
  );
}
