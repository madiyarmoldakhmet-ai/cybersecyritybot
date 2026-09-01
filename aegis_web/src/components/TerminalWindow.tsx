import { useEffect, useRef, useState } from 'react';
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
    case 'CodeAnalyzing': return <Shield className="w-4 h-4 text-cyan-400" />;
    case 'VulnerabilityFound': return <Bug className="w-4 h-4 text-red-400" />;
    case 'ScanCompleted': return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'SystemLog': return <Terminal className="w-4 h-4 text-gray-400" />;
    case 'SystemError': return <Bug className="w-4 h-4 text-red-500" />;
    default: return <Terminal className="w-4 h-4 text-gray-400" />;
  }
};

const TypewriterText = ({ text, onComplete }: { text: string, onComplete?: () => void }) => {
  const [displayed, setDisplayed] = useState('');
  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      setDisplayed(text.substring(0, i));
      i++;
      if (i > text.length) {
        clearInterval(interval);
        if (onComplete) onComplete();
      }
    }, 15); // Fast hacking speed
    return () => clearInterval(interval);
  }, [text, onComplete]);
  return <span>{displayed}</span>;
};

export function TerminalWindow({ events, className }: TerminalWindowProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  // Smooth scroll to bottom when new events arrive
  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events]);

  return (
    <div className={cn("flex flex-col bg-slate-950/80 backdrop-blur-md rounded-xl overflow-hidden border border-slate-800 shadow-2xl", className)}>
      {/* Terminal Header */}
      <div className="flex items-center px-4 py-2 bg-slate-900 border-b border-slate-800">
        <div className="flex gap-2 mr-4">
          <div className="w-3 h-3 rounded-full bg-red-500" />
          <div className="w-3 h-3 rounded-full bg-yellow-500" />
          <div className="w-3 h-3 rounded-full bg-green-500" />
        </div>
        <span className="text-xs text-slate-400 font-mono tracking-wider">AEGIS.OS // SCANNER_TERMINAL</span>
      </div>

      {/* Terminal Content */}
      <div 
        className="flex-1 p-4 overflow-y-auto font-mono text-sm space-y-2 relative"
      >
        <AnimatePresence initial={false}>
          {events.map((event, idx) => {
            const isLast = idx === events.length - 1;
            const isCritical = event.severity?.toLowerCase() === 'critical';
            const isCodeAnalyzing = event.event_type === 'CodeAnalyzing';
            
            return (
              <motion.div
                key={idx}
                initial={{ opacity: 0, x: -10 }}
                animate={isCritical ? { opacity: 1, x: [-10, 10, -10, 10, 0] } : { opacity: 1, x: 0 }}
                transition={isCritical ? { duration: 0.4 } : { duration: 0.2 }}
                className={cn(
                  "flex items-start gap-3 p-2 rounded",
                  isCritical && "bg-red-950/30 border-l-2 border-red-500"
                )}
              >
                <div className="mt-0.5">{getEventIcon(event.event_type)}</div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500 text-xs">
                      [{new Date(event.timestamp || Date.now()).toLocaleTimeString()}]
                    </span>
                    <span className={cn(
                      "font-semibold uppercase tracking-wider text-xs",
                      event.event_type === 'VulnerabilityFound' || event.event_type === 'SystemError' ? 'text-red-400' :
                      event.event_type === 'FileScanning' ? 'text-emerald-400' :
                      event.event_type === 'CodeAnalyzing' ? 'text-cyan-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.8)]' :
                      'text-slate-300'
                    )}>
                      {event.event_type}
                    </span>
                  </div>
                  
                  {/* Event Details */}
                  <div className="text-slate-300 mt-1 pl-1 border-l-2 border-slate-800 ml-1">
                    {event.file_path && (
                      <div className="text-slate-400">Target: <span className="text-emerald-300">{event.file_path}</span></div>
                    )}
                    
                    {event.title && (
                      <div className={cn("font-semibold mt-1", isCritical ? "text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.8)]" : "text-red-300")}>
                        [!] {event.title}
                      </div>
                    )}

                    {event.message && (
                      <div className="text-slate-400 mt-1">
                        <TypewriterText text={event.message} />
                        {isLast && !event.snippet && <span className="animate-pulse ml-1">_</span>}
                      </div>
                    )}

                    {event.snippet && (
                      <div className={cn(
                        "mt-2 font-mono p-3 rounded text-xs overflow-x-auto",
                        isCritical 
                          ? "bg-red-950/50 text-red-400 border border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.3)]"
                          : isCodeAnalyzing
                          ? "bg-cyan-950/30 text-cyan-300 border border-cyan-500/30 shadow-[0_0_10px_rgba(34,211,238,0.3)]" 
                          : "bg-slate-900 text-slate-400"
                      )}>
                        <TypewriterText text={event.snippet} />
                        {isLast && <span className="animate-pulse ml-1 text-white">_</span>}
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
        
        {events.length === 0 && (
          <div className="text-slate-500 italic">SYSTEM.WAITING_FOR_INPUT<span className="animate-pulse">_</span></div>
        )}
        
        {/* Invisible div for auto-scrolling */}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
