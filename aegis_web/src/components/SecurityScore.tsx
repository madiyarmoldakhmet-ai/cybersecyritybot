'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

interface SecurityScoreProps {
  score: number;
  grade?: string;
  className?: string;
}

export function SecurityScore({ score, grade, className }: SecurityScoreProps) {
  const isPerfect = score === 100;
  const isGood = score >= 80;
  const isWarning = score >= 50 && score < 80;

  const colorClass =
    isPerfect || isGood
      ? 'text-emerald-400 stroke-emerald-400'
      : isWarning
      ? 'text-amber-400 stroke-amber-400'
      : 'text-red-400 stroke-red-400';

  const circumference = 2 * Math.PI * 42;
  const strokeDashoffset = circumference - (Math.max(0, Math.min(100, score)) / 100) * circumference;

  const label = grade
    ? `Grade ${grade} · ${isPerfect || isGood ? 'Безопасно' : isWarning ? 'Нужен фикс' : 'Критичный риск'}`
    : isPerfect
    ? 'Отлично'
    : isGood
    ? 'Хорошо'
    : isWarning
    ? 'Средний риск'
    : 'Критичный риск';

  return (
    <div className={cn('bg-[#1f1e1b] border border-[#2b2926] rounded-xl p-4 flex items-center gap-5', className)}>
      <div className="relative w-24 h-24 shrink-0 flex items-center justify-center">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100" aria-hidden="true">
          <circle cx="50" cy="50" r="42" fill="none" strokeWidth="8" className="stroke-[#2b2926]" />
          <motion.circle
            cx="50"
            cy="50"
            r="42"
            fill="none"
            strokeWidth="8"
            className={colorClass}
            strokeLinecap="round"
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 0.7, ease: 'easeOut' }}
            style={{ strokeDasharray: circumference }}
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className={cn('text-2xl font-bold font-mono leading-none', colorClass.split(' ')[0])}>
            {score}
          </span>
          <span className="text-[10px] text-[#8e8b82] font-mono mt-0.5">/ 100</span>
        </div>
      </div>

      <div className="min-w-0">
        <div className="text-xs font-mono uppercase tracking-wider text-[#a09d96]">Security Score</div>
        <div className={cn('flex items-center gap-1.5 font-semibold text-base mt-1', colorClass.split(' ')[0])}>
          {isGood ? <ShieldCheck className="w-4 h-4 shrink-0" /> : <ShieldAlert className="w-4 h-4 shrink-0" />}
          <span className="truncate">{label}</span>
        </div>
        <p className="text-xs text-[#a09d96] mt-1">
          Оценка на основе критичности находок SAST, Taint и Secret сканеров.
        </p>
      </div>
    </div>
  );
}
