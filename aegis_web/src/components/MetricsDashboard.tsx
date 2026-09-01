'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Shield, FileWarning, Clock, Files } from 'lucide-react';

interface MetricsDashboardProps {
  scannedFiles: number;
  totalFiles: number;
  vulnerabilities: number;
  elapsedTime: number; // in seconds
  className?: string;
}

export function MetricsDashboard({ scannedFiles, totalFiles, vulnerabilities, elapsedTime, className }: MetricsDashboardProps) {
  const progress = totalFiles > 0 ? (scannedFiles / totalFiles) * 100 : 0;

  return (
    <div className={cn("grid grid-cols-2 lg:grid-cols-4 gap-4", className)}>
      <MetricCard 
        title="Files Scanned" 
        value={`${scannedFiles} / ${totalFiles || '?'}`} 
        icon={<Files className="w-5 h-5 text-blue-400" />} 
        progress={progress}
      />
      <MetricCard 
        title="Vulnerabilities" 
        value={vulnerabilities} 
        icon={<FileWarning className={cn("w-5 h-5", vulnerabilities > 0 ? "text-red-400" : "text-green-400")} />} 
        valueColor={vulnerabilities > 0 ? "text-red-400" : "text-green-400"}
      />
      <MetricCard 
        title="Elapsed Time" 
        value={`${elapsedTime}s`} 
        icon={<Clock className="w-5 h-5 text-purple-400" />} 
      />
      <MetricCard 
        title="Engine Status" 
        value={progress === 100 ? 'Completed' : 'Running'} 
        icon={<Shield className={cn("w-5 h-5", progress === 100 ? "text-green-400" : "text-emerald-400")} />} 
        valueColor={progress === 100 ? 'text-green-400' : 'text-emerald-400'}
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
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden">
      {progress !== undefined && (
        <motion.div 
          className="absolute bottom-0 left-0 h-1 bg-blue-500/30"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.3 }}
        />
      )}
      <div className="flex justify-between items-center mb-4">
        <span className="text-slate-400 text-sm font-medium">{title}</span>
        {icon}
      </div>
      <div className={cn("text-2xl font-bold font-mono tracking-tight", valueColor || "text-slate-100")}>
        {value}
      </div>
    </div>
  );
}
