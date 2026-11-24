'use client';

import { useEffect, useRef } from 'react';
import { cn } from '@/lib/utils';

type EventType =
  | 'ScanStarted'
  | 'FileScanning'
  | 'CodeAnalyzing'
  | 'VulnerabilityFound'
  | 'ScanCompleted'
  | 'SystemLog'
  | 'SystemError';

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
  targetLabel?: string;
  className?: string;
}

export function TerminalWindow({ events, targetLabel, className }: TerminalWindowProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, [events]);

  return (
    <div
      className={cn(
        'pixel-card flex flex-col bg-[#080c16] text-[#eef6ff] overflow-hidden',
        className
      )}
    >
      <div className="flex items-center justify-between px-3 py-2 border-b-2 border-[#30436b] bg-[#121829]">
        <div className="flex items-center gap-1.5" aria-hidden="true">
          <span className="w-2.5 h-2.5 bg-[#e94a32]" />
          <span className="w-2.5 h-2.5 bg-[#ffe79e]" />
          <span className="w-2.5 h-2.5 bg-[#47d18c]" />
        </div>
        <span className="font-mono text-[11px] text-[#93add1] truncate">
          {targetLabel ? `~/aegis — ${targetLabel}` : '~/aegis — stream'}
        </span>
        <span className="w-6" aria-hidden="true" />
      </div>

      <div
        role="log"
        aria-label="Журнал сканирования"
        className="cg-scroll flex-1 p-3 overflow-y-auto font-mono text-[12px] leading-relaxed space-y-2 min-h-[190px] max-h-[290px]"
      >
        {events.length === 0 ? (
          <div className="space-y-1 text-[#93add1]">
            <div>
              <span className="text-[#56d4b2]">$</span> <code>aegis scan --policy .aegis.yml --local-only</code>
            </div>
            <div className="text-[#7893ba]">
              SAST · межфайловый Taint · Backdoor · System Analyst · ИИН
            </div>
          </div>
        ) : (
          events.map((event, idx) => {
            const isFinding =
              event.event_type === 'VulnerabilityFound' || event.event_type === 'SystemError';
            const isDone = event.event_type === 'ScanCompleted';

            return (
              <div
                key={idx}
                className={cn(
                  'border-l-2 pl-2 py-0.5',
                  isFinding
                    ? 'border-[#e94a32]'
                    : isDone
                    ? 'border-[#47d18c]'
                    : 'border-[#30436b]'
                )}
              >
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className="text-[#7893ba] tabular-nums">
                    {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'LIVE'}
                  </span>
                  <span
                    className={cn(
                      'uppercase tracking-wider',
                      isFinding
                        ? 'text-[#ff7b66]'
                        : isDone
                        ? 'text-[#47d18c]'
                        : 'text-[#c9e4ff]'
                    )}
                  >
                    {event.event_type}
                  </span>
                </div>
                {event.file_path && (
                  <div className="text-[#56d4b2] truncate"><code>{event.file_path}</code></div>
                )}
                {event.title && (
                  <div className="text-[#eef6ff] break-words">{event.title}</div>
                )}
                {event.message && (
                  <div className="text-[#93add1] break-words">{event.message}</div>
                )}
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
