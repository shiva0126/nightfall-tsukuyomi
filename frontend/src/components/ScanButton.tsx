import { motion } from 'framer-motion';
import { Zap } from 'lucide-react';

interface ScanButtonProps {
  onClick: () => void;
  loading?: boolean;
}

export default function ScanButton({ onClick, loading }: ScanButtonProps) {
  return (
    <motion.button
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      onClick={onClick}
      disabled={loading}
      className="relative px-8 py-4 bg-gradient-to-r from-cyber-purple via-cyber-pink to-cyber-cyan rounded-xl font-bold text-white text-lg overflow-hidden group disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {/* Animated background */}
      <div className="absolute inset-0 bg-gradient-to-r from-cyber-cyan via-cyber-pink to-cyber-purple opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      
      {/* Glow effect */}
      <div className="absolute inset-0 blur-xl bg-cyber-purple/50 group-hover:bg-cyber-cyan/50 transition-colors duration-300" />
      
      <div className="relative z-10 flex items-center gap-2">
        {loading ? (
          <>
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            >
              <Zap className="w-5 h-5" />
            </motion.div>
            <span>SCANNING...</span>
          </>
        ) : (
          <>
            <Zap className="w-5 h-5" />
            <span>START SCAN</span>
          </>
        )}
      </div>
    </motion.button>
  );
}
