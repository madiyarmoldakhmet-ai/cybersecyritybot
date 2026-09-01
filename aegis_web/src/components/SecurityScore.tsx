'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

interface SecurityScoreProps {
  score: number;
  className?: string;
}

export function SecurityScore({ score, className }: SecurityScoreProps) {
  // Score is 0-100 (100 = perfect)
  const isPerfect = score === 100;
  const isGood = score >= 80;
  const isWarning = score >= 50 && score < 80;
  const isDanger = score < 50;

  const colorClass = isPerfect || isGood 
    ? 'text-emerald-400 stroke-emerald-400' 
    : isWarning 
    ? 'text-yellow-400 stroke-yellow-400' 
    : 'text-red-500 stroke-red-500';

  const circumference = 2 * Math.PI * 45; // r=45
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={cn("bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col items-center justify-center relative", className)}>
      <div className="absolute top-4 left-4 text-slate-400 text-sm font-medium">Security Score</div>
      
      <div className="relative w-40 h-40 mt-4 flex items-center justify-center">
        {/* Background Circle */}
        <svg className="absolute w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            strokeWidth="8"
            className="stroke-slate-800"
          />
          {/* Progress Circle */}
          <motion.circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            strokeWidth="8"
            className={colorClass}
            strokeLinecap="round"
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1, ease: "easeOut" }}
            style={{
              strokeDasharray: circumference,
            }}
          />
        </svg>

        <div className="absolute flex flex-col items-center justify-center">
          <div className={cn("text-4xl font-bold font-mono", colorClass.split(' ')[0])}>
            {score}
          </div>
        </div>
      </div>

      <div className="mt-6 flex items-center gap-2">
        {isPerfect || isGood ? (
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
        ) : (
          <ShieldAlert className={cn("w-5 h-5", colorClass.split(' ')[0])} />
        )}
        <span className={cn("font-medium", colorClass.split(' ')[0])}>
          {isPerfect ? "Perfect" : isGood ? "Good" : isWarning ? "Warning" : "Critical Risk"}
        </span>
      </div>
    </div>
  );
}
