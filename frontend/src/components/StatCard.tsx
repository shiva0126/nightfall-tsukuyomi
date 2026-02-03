import { motion } from 'framer-motion';
import { type LucideProps } from 'lucide-react';
import { ForwardRefExoticComponent, RefAttributes } from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: ForwardRefExoticComponent<Omit<LucideProps, "ref"> & RefAttributes<SVGSVGElement>>;
  trend?: string;
  color?: string;
}

export default function StatCard({ title, value, icon: Icon, trend, color = 'cyber-purple' }: StatCardProps) {
  return (
    <motion.div
      whileHover={{ scale: 1.02, y: -5 }}
      className="glass-card p-6 relative overflow-hidden group"
    >
      {/* Animated background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-cyber-purple/10 to-cyber-cyan/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className={`p-3 rounded-xl bg-${color}/20 border border-${color}/30`}>
            <Icon className={`w-6 h-6 text-${color}`} />
          </div>
          {trend && (
            <span className="text-sm text-green-400">+{trend}</span>
          )}
        </div>
        
        <div className="text-3xl font-black text-white mb-1">
          {value}
        </div>
        <div className="text-sm text-gray-400 uppercase tracking-wider">
          {title}
        </div>
      </div>
    </motion.div>
  );
}
