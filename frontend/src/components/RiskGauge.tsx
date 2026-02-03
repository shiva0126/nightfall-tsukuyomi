import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

interface RiskGaugeProps {
  score: number;
}

export default function RiskGauge({ score }: RiskGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(score), 100);
    return () => clearTimeout(timer);
  }, [score]);

  const getRiskLevel = (score: number) => {
    if (score <= 30) return { label: 'LOW', color: '#00ff00', gradient: 'from-green-500 to-emerald-600' };
    if (score <= 70) return { label: 'MEDIUM', color: '#fbbf24', gradient: 'from-yellow-500 to-orange-500' };
    return { label: 'HIGH', color: '#ef4444', gradient: 'from-red-500 to-rose-700' };
  };

  const risk = getRiskLevel(score);
  const circumference = 2 * Math.PI * 120;
  const offset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="relative w-64 h-64">
      <svg className="transform -rotate-90 w-full h-full">
        {/* Background circle */}
        <circle
          cx="128"
          cy="128"
          r="120"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth="20"
          fill="none"
        />
        
        {/* Animated progress circle */}
        <motion.circle
          cx="128"
          cy="128"
          r="120"
          stroke={risk.color}
          strokeWidth="20"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 2, ease: "easeInOut" }}
          className="filter drop-shadow-[0_0_10px_rgba(168,85,247,0.8)]"
        />
      </svg>

      {/* Center text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.5, type: "spring" }}
          className="text-center"
        >
          <div className="text-6xl font-black text-white mb-2">
            {animatedScore}
          </div>
          <div className="text-sm text-gray-400">RISK SCORE</div>
          <div className={`text-2xl font-bold mt-2 bg-gradient-to-r ${risk.gradient} text-transparent bg-clip-text`}>
            {risk.label}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
