import { motion } from 'framer-motion';

interface RiskGaugeProps {
  score: number;
}

export default function RiskGauge({ score }: RiskGaugeProps) {
  const getColor = () => {
    if (score >= 70) return 'from-red-500 to-orange-500';
    if (score >= 40) return 'from-yellow-500 to-orange-500';
    return 'from-green-500 to-cyan-500';
  };

  const getRiskLevel = () => {
    if (score >= 70) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-32 h-32">
        <svg className="transform -rotate-90 w-32 h-32">
          <circle
            cx="64"
            cy="64"
            r="56"
            stroke="currentColor"
            strokeWidth="8"
            fill="transparent"
            className="text-slate-700"
          />
          <motion.circle
            cx="64"
            cy="64"
            r="56"
            stroke="url(#gradient)"
            strokeWidth="8"
            fill="transparent"
            strokeDasharray={`${2 * Math.PI * 56}`}
            initial={{ strokeDashoffset: 2 * Math.PI * 56 }}
            animate={{ strokeDashoffset: 2 * Math.PI * 56 * (1 - score / 100) }}
            transition={{ duration: 1, ease: "easeOut" }}
            strokeLinecap="round"
          />
          <defs>
            <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" className={`${getColor().split(' ')[0].replace('from-', '')}`} />
              <stop offset="100%" className={`${getColor().split(' ')[1].replace('to-', '')}`} />
            </linearGradient>
          </defs>
        </svg>
        <div className="absolute inset-0 flex items-center justify-center flex-col">
          <div className="text-2xl font-black text-white">{score}</div>
          <div className="text-xs text-slate-400">/ 100</div>
        </div>
      </div>
      <div className={`mt-2 text-sm font-bold bg-gradient-to-r ${getColor()} bg-clip-text text-transparent`}>
        {getRiskLevel()} RISK
      </div>
    </div>
  );
}
