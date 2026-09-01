'use client';

import { useEffect, useRef } from 'react';
import { cn } from '@/lib/utils';
import { Terminal, Shield, FileSearch, Bug, CheckCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

type EventType = 'ScanStarted' | 'FileScanning' | 'CodeAnalyzing' | 'VulnerabilityFound' | 'ScanCompleted' | 'SystemLog' | 'SystemError';

export interface ScanEvent {
  event_type: EventType;
  timestamp?: string;
  file_path?: string;
  snippet?: string;
  severity?: string;
  title?: string;
  message?: string;
  total_files?: number;
  total_findings?: number;
}

interface TerminalWindowProps {
  events: ScanEvent[];
  className?: string;
}

const getEventIcon = (type: EventType) => {
  switch (type) {
    case 'ScanStarted': return <Terminal className="w-4 h-4 text-blue-400" />;
    case 'FileScanning': return <FileSearch className="w-4 h-4 text-emerald-400" />;
    case 'CodeAnalyzing': return <Shield className="w-4 h-4 text-purple-400" />;
    case 'VulnerabilityFound': return <Bug className="w-4 h-4 text-red-400" />;
    case 'ScanCompleted': return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'SystemLog': return <Terminal className="w-4 h-4 text-gray-400" />;
    case 'SystemError': return <Bug className="w-4 h-4 text-red-500" />;
    default: return <Terminal className="w-4 h-4 text-gray-400" />;
  }
};

export function TerminalWindow({ events, className }: TerminalWindowProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className={cn("flex flex-col bg-slate-950 rounded-xl overflow-hidden border border-slate-800 shadow-2xl", className)}>
      {/* Terminal Header */}
      <div className="flex items-center px-4 py-2 bg-slate-900 border-b border-slate-800">
        <div className="flex gap-2 mr-4">
          <div className="w-3 h-3 rounded-full bg-red-500" />
          <div className="w-3 h-3 rounded-full bg-yellow-500" />
          <div className="w-3 h-3 rounded-full bg-green-500" />
        </div>
        <span className="text-xs text-slate-400 font-mono">aegis-core-engine ~ scan</span>
      </div>

      {/* Terminal Content */}
      <div 
        ref={scrollRef}
        className="flex-1 p-4 overflow-y-auto font-mono text-sm"
      >
        <AnimatePresence initial={false}>
          {events.map((event, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-start gap-3 mb-2"
            >
              <div className="mt-0.5">{getEventIcon(event.event_type)}</div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-xs">
                    [{new Date(event.timestamp || Date.now()).toLocaleTimeString()}]
                  </span>
                  <span className={cn(
                    "font-semibold",
                    event.event_type === 'VulnerabilityFound' || event.event_type === 'SystemError' ? 'text-red-400' :
                    event.event_type === 'FileScanning' ? 'text-emerald-400' :
                    event.event_type === 'CodeAnalyzing' ? 'text-purple-400' :
                    'text-slate-300'
                  )}>
                    {event.event_type}
                  </span>
                </div>
                
                {/* Event Details */}
                <div className="text-slate-300 mt-1 pl-1 border-l-2 border-slate-800 ml-1">
                  {event.file_path && (
                    <div className="text-slate-400">File: <span className="text-emerald-200">{event.file_path}</span></div>
                  )}
                  {event.message && (
                    <div className="text-slate-400">{event.message}</div>
                  )}
                  {event.title && (
                    <div className="text-red-300 font-semibold">{event.title}</div>
                  )}
                  {event.snippet && (
                    <div className="text-slate-400 text-xs mt-1 font-mono bg-slate-900 p-2 rounded">
                      {event.snippet}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
        {events.length === 0 && (
          <div className="text-slate-500 italic">Waiting for scan events...</div>
        )}
      </div>
    </div>
  );
}
