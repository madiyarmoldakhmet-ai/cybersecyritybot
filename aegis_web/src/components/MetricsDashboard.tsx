'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Shield, FileWarning, Clock, Files } from 'lucide-react';

interface MetricsDashboardProps {
  scannedFiles: number;
  totalFiles: number;
  vulnerabilities: number;
  elapsedTime: number;
  securityScore?: number | null;
  grade?: string | null;
  isScanning?: boolean;
  className?: string;
}

export function MetricsDashboard({
  scannedFiles,
  totalFiles,
  vulnerabilities,
  elapsedTime,
  securityScore,
  grade,
  isScanning = false,
  className,
}: MetricsDashboardProps) {
  const progress = totalFiles > 0 ? Math.min(100, (scannedFiles / totalFiles) * 100) : isScanning ? 35 : 0;

  return (
    <div className={cn('grid grid-cols-2 lg:grid-cols-4 gap-3', className)}>
      <MetricCard
        title="Файлов"
        value={totalFiles > 0 ? `${scannedFiles} / ${totalFiles}` : `${scannedFiles || 0}`}
        icon={<Files className="w-4 h-4 text-blue-400" />}
        progress={isScanning || totalFiles > 0 ? progress : undefined}
      />
      <MetricCard
        title="Уязвимости"
        value={vulnerabilities}
        icon={<FileWarning className={cn('w-4 h-4', vulnerabilities > 0 ? 'text-red-400' : 'text-emerald-400')} />}
        valueColor={vulnerabilities > 0 ? 'text-red-400' : 'text-emerald-400'}
      />
      <MetricCard
        title="Время"
        value={`${elapsedTime.toFixed(1).replace(/\.0$/, '')} с`}
        icon={<Clock className="w-4 h-4 text-purple-400" />}
      />
      <MetricCard
        title="Score / Статус"
        value={
          isScanning
            ? 'Сканирую...'
            : securityScore !== null && securityScore !== undefined
            ? `${securityScore}/100 (${grade || '-'})`
            : 'Готов'
        }
        icon={<Shield className={cn('w-4 h-4', isScanning ? 'text-amber-400' : 'text-emerald-400')} />}
        valueColor={
          isScanning
            ? 'text-amber-400'
            : securityScore !== null && securityScore !== undefined && securityScore < 50
            ? 'text-red-400'
            : 'text-emerald-400'
        }
      />
    </div>
  );
}

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  progress?: number;
  valueColor?: string;
}

function MetricCard({ title, value, icon, progress, valueColor }: MetricCardProps) {
  return (
    <div className="bg-[#1f1e1b] border border-[#2b2926] rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden">
      {progress !== undefined && (
        <motion.div
          className="absolute bottom-0 left-0 h-0.5 bg-[var(--color-primary)]"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.3 }}
        />
      )}
      <div className="flex justify-between items-center mb-2">
        <span className="text-[#a09d96] text-xs font-medium">{title}</span>
        {icon}
      </div>
      <div className={cn('text-lg font-bold font-mono tracking-tight truncate', valueColor || 'text-[#faf9f5]')}>
        {value}
      </div>
    </div>
  );
}
