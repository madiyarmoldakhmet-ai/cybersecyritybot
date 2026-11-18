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
        'flex flex-col bg-[#0a0a0a] text-[#ededed] border border-[var(--color-line)] rounded-xl overflow-hidden',
        className
      )}
    >
      <div className="flex items-center justify-between px-3.5 py-2 border-b border-[#232323] bg-[#111111]">
        <div className="flex items-center gap-1.5" aria-hidden="true">
          <span className="w-2 h-2 rounded-full bg-[#383838]" />
          <span className="w-2 h-2 rounded-full bg-[#383838]" />
          <span className="w-2 h-2 rounded-full bg-[#383838]" />
        </div>
        <span className="font-mono text-[11px] text-[#8f8f8f] truncate">
          {targetLabel ? `~/aegis — ${targetLabel}` : '~/aegis — stream'}
        </span>
        <span className="w-6" aria-hidden="true" />
      </div>

      <div
        role="log"
        aria-label="Журнал сканирования"
        className="cg-scroll flex-1 p-3 overflow-y-auto font-mono text-[11.5px] leading-relaxed space-y-2 min-h-[190px] max-h-[290px]"
      >
        {events.length === 0 ? (
          <div className="space-y-1 text-[#8f8f8f]">
            <div>
              <span className="text-[#e94a32]">$</span> aegis scan --policy .aegis.yml --local-only
            </div>
            <div className="text-[#6c6c6c]">
              SAST · межфайловый Taint · ИИН/секреты (0 bytes external)
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
                    ? 'border-[#3fbf7f]'
                    : 'border-[#232323]'
                )}
              >
                <div className="flex flex-wrap items-center gap-2 text-[10.5px]">
                  <span className="text-[#6c6c6c] tabular-nums">
                    {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'LIVE'}
                  </span>
                  <span
                    className={cn(
                      'uppercase tracking-wider',
                      isFinding
                        ? 'text-[#e94a32]'
                        : isDone
                        ? 'text-[#3fbf7f]'
                        : 'text-[#c9c9c9]'
                    )}
                  >
                    {event.event_type}
                  </span>
                </div>
                {event.file_path && (
                  <div className="text-[#3fbf7f] truncate">{event.file_path}</div>
                )}
                {event.title && (
                  <div className="text-[#ededed] break-words">{event.title}</div>
                )}
                {event.message && (
                  <div className="text-[#8f8f8f] break-words">{event.message}</div>
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
