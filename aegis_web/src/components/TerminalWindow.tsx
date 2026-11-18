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
        'flex flex-col bg-[#111111] text-[#ededed] border border-[#242424] overflow-hidden',
        className
      )}
    >
      {/* Card Header */}
      <div className="px-5 pt-4 pb-3 border-b border-[#242424] flex items-baseline justify-between gap-2">
        <span className="font-mono text-xl tracking-tight text-[#ededed]">Mono</span>
        <span className="font-mono text-xs text-[#8f8f8f]">Поток сканирования</span>
      </div>

      {/* Embedded zsh-style terminal frame inspired by prtner.ai Mono card */}
      <div className="p-4 flex-1 flex flex-col min-h-0">
        <div className="flex-1 flex flex-col bg-[#0a0a0a] border border-[#242424] rounded-lg overflow-hidden min-h-0">
          <div className="flex items-center justify-between px-3.5 py-2 border-b border-[#1c1c1c] bg-[#141414]">
            <div className="flex items-center gap-1.5" aria-hidden="true">
              <span className="w-2.5 h-2.5 rounded-full bg-[#3d3d3d]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#3d3d3d]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#3d3d3d]" />
            </div>
            <span className="font-mono text-[11px] text-[#8f8f8f] truncate">
              {targetLabel ? `~/aegis — ${targetLabel}` : '~/aegis — zsh'}
            </span>
            <span className="w-8" aria-hidden="true" />
          </div>

          <div
            role="log"
            aria-label="Журнал работы сканера"
            className="cg-scroll flex-1 p-3.5 overflow-y-auto font-mono text-xs leading-relaxed space-y-2.5 min-h-[220px] max-h-[340px]"
          >
            {events.length === 0 ? (
              <div className="space-y-1.5 text-[#8f8f8f]">
                <div>
                  <span className="text-[#e94a32]">$</span> aegis scan --policy .aegis.yml --local-only
                </div>
                <div className="text-[#6b6a65]">
                  ready · SAST + межфайловый Taint + ИИН/секреты (0 байт в облако)
                </div>
                <div>
                  <span className="text-[#ededed]">cursor:</span> ожидание GitHub URL, ZIP или «Демо-аудита»
                  <span className="inline-block w-1.5 h-3.5 ml-1 bg-[#e94a32] align-middle animate-pulse" />
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
                      'border-l-2 pl-2.5 py-0.5',
                      isFinding
                        ? 'border-[#e94a32]'
                        : isDone
                        ? 'border-emerald-400'
                        : 'border-[#242424]'
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-2 text-[11px]">
                      <span className="text-[#6b6a65] tabular-nums">
                        {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'LIVE'}
                      </span>
                      <span
                        className={cn(
                          'uppercase tracking-wider',
                          isFinding
                            ? 'text-[#e94a32]'
                            : isDone
                            ? 'text-emerald-400'
                            : 'text-[#b8b8b2]'
                        )}
                      >
                        {event.event_type}
                      </span>
                      {event.severity && (
                        <span className="px-1.5 py-0.2 bg-[#1a1a1a] border border-[#2d2d2d] text-[#ededed] text-[10px]">
                          {event.severity}
                        </span>
                      )}
                    </div>

                    {event.file_path && (
                      <div className="text-[#b8b8b2] mt-0.5 break-all">
                        target: <span className="text-emerald-400">{event.file_path}</span>
                      </div>
                    )}
                    {event.title && (
                      <div className="text-[#ededed] font-medium mt-0.5">{event.title}</div>
                    )}
                    {event.message && (
                      <div className="text-[#8f8f8f] mt-0.5 break-words">{event.message}</div>
                    )}
                    {event.snippet && (
                      <pre className="mt-1.5 p-2 bg-[#141414] border border-[#242424] rounded text-[11px] overflow-x-auto text-[#d6d3cd]">
                        {event.snippet}
                      </pre>
                    )}
                  </div>
                );
              })
            )}
            <div ref={bottomRef} />
          </div>
        </div>
      </div>
    </div>
  );
}
