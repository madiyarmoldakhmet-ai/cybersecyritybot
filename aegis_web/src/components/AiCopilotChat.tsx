'use client';

import { FormEvent, KeyboardEvent, ReactNode, useEffect, useId, useRef, useState } from 'react';
import { Paperclip, RotateCcw, Send, Shield, Upload } from 'lucide-react';
import { cn } from '@/lib/utils';

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
};

interface AiCopilotChatProps {
  messages: ChatMessage[];
  input: string;
  onInputChange: (value: string) => void;
  onSubmit: (e: FormEvent) => void;
  onQuickPrompt: (prompt: string) => void;
  onResetChat: () => void;
  onUploadZip: (file: File) => void;
  isTyping: boolean;
  isScanning: boolean;
  ollamaOnline: boolean | null;
  ollamaModel: string;
  activeTarget: string;
  className?: string;
}

const QUICK_PROMPTS = [
  'Объясни критичные баги',
  'Патч от SQL-инъекции',
  'Политика .aegis.yml и ИИН',
  '94-V ФЗ vs облачные LLM',
];

function renderInlineFormatting(line: string, keyPrefix: string): ReactNode[] {
  const tokens = line.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return tokens.map((token, idx) => {
    if (token.startsWith('`') && token.endsWith('`') && token.length >= 2) {
      return (
        <code
          key={`${keyPrefix}-${idx}`}
          className="font-mono text-[0.86em] px-1 py-0.5 rounded bg-black/10 break-words"
        >
          {token.slice(1, -1)}
        </code>
      );
    }
    if (token.startsWith('**') && token.endsWith('**') && token.length >= 4) {
      return (
        <strong key={`${keyPrefix}-${idx}`} className="font-semibold">
          {token.slice(2, -2)}
        </strong>
      );
    }
    return <span key={`${keyPrefix}-${idx}`}>{token}</span>;
  });
}

function FormattedBubbleContent({ content, isUser }: { content: string; isUser: boolean }) {
  const segments = content.split(/(```[\s\S]*?```)/g);

  return (
    <div className="space-y-2 text-[14.5px] leading-[1.48] break-words [overflow-wrap:anywhere]">
      {segments.map((segment, segIdx) => {
        if (segment.startsWith('```') && segment.endsWith('```') && segment.length >= 6) {
          const inner = segment.slice(3, -3).replace(/^[a-zA-Z0-9_-]+\n/, '');
          return (
            <pre
              key={`code-${segIdx}`}
              className={cn(
                'font-mono text-xs p-2.5 rounded-lg overflow-x-auto border',
                isUser
                  ? 'bg-black/40 border-white/15 text-[#f4f4f0]'
                  : 'bg-[#141414] border-[#242424] text-[#ededed]'
              )}
            >
              <code>{inner.trim()}</code>
            </pre>
          );
        }

        const lines = segment.split('\n');
        return lines.map((line, lineIdx) => (
          <p key={`txt-${segIdx}-${lineIdx}`} className={line.trim() ? '' : 'h-1'}>
            {renderInlineFormatting(line, `${segIdx}-${lineIdx}`)}
          </p>
        ));
      })}
    </div>
  );
}

export function AiCopilotChat({
  messages,
  input,
  onInputChange,
  onSubmit,
  onQuickPrompt,
  onResetChat,
  onUploadZip,
  isTyping,
  isScanning,
  ollamaOnline,
  ollamaModel,
  activeTarget,
  className,
}: AiCopilotChatProps) {
  const inputId = useId();
  const fileInputId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const [isDraggingZip, setIsDraggingZip] = useState(false);

  useEffect(() => {
    const container = logContainerRef.current;
    if (!container) return;
    container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' });
  }, [messages, isTyping]);

  // IME-safe Enter-to-submit (modern-web-guidance: ime-safe-enter-submit)
  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (e.nativeEvent.isComposing || e.keyCode === 229) {
        return;
      }
      if (input.trim() && !isTyping) {
        formRef.current?.requestSubmit();
      }
    }
  };

  return (
    <section
      aria-label="Чат с локальным AI-аудитором"
      className={cn(
        'bg-[#f4f4f0] text-[#141414] border border-[var(--color-line)] flex flex-col relative',
        className
      )}
      onDragOver={(e) => {
        e.preventDefault();
        setIsDraggingZip(true);
      }}
      onDragLeave={() => setIsDraggingZip(false)}
      onDrop={(e) => {
        e.preventDefault();
        setIsDraggingZip(false);
        const file = e.dataTransfer.files?.[0];
        if (file) onUploadZip(file);
      }}
    >
      {/* Top Specimen Header matching prtner.ai/font Sans showcase */}
      <div className="px-5 pt-4 pb-3 border-b border-[#d8d7d0] flex items-baseline justify-between gap-3">
        <div className="flex items-baseline gap-2.5">
          <h2 className="font-sans text-2xl font-normal tracking-tight text-[#141414]">
            AI-Чат
          </h2>
          <span className="font-mono text-[11px] uppercase tracking-wider text-[#6b6a65]">
            Qwen / Ollama
          </span>
        </div>
        <button
          type="button"
          onClick={onResetChat}
          className="min-h-8 px-2.5 py-1 border border-[#d8d7d0] hover:border-[#141414] bg-white/80 text-[#141414] font-mono text-[11px] uppercase tracking-wider inline-flex items-center gap-1.5 transition-colors cursor-pointer"
        >
          <RotateCcw className="w-3 h-3" aria-hidden="true" />
          <span>Сброс</span>
        </button>
      </div>

      {/* Embedded Mobile/App Chat Surface inspired by Кафе «Медеу» card */}
      <div className="p-4 sm:p-5 flex-1 flex flex-col min-h-0">
        <div className="bg-white border-2 border-[#141414] rounded-[24px] shadow-[0_14px_38px_-14px_rgba(20,20,20,0.22)] flex flex-col flex-1 overflow-hidden min-h-[460px] max-h-[680px]">
          {/* App Chat Header */}
          <div className="px-4 py-3 border-b border-[#ecebe4] flex items-center justify-between gap-3 shrink-0 bg-white">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-full bg-[#141414] text-white flex items-center justify-center shrink-0">
                <Shield className="w-4 h-4 text-[#e94a32]" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <div className="font-sans font-semibold text-[15px] leading-tight text-[#141414] truncate">
                  Commit Guardian AI
                </div>
                <div className="flex items-center gap-1.5 text-xs mt-0.5 truncate">
                  <span
                    className={cn(
                      'w-1.5 h-1.5 rounded-full shrink-0',
                      ollamaOnline ? 'bg-emerald-600' : 'bg-[#e94a32]'
                    )}
                    aria-hidden="true"
                  />
                  <span className={ollamaOnline ? 'text-emerald-700' : 'text-[#6b6a65]'}>
                    {ollamaOnline
                      ? `ассистент на связи · ${ollamaModel}`
                      : `SAST готов · ${ollamaModel}`}
                  </span>
                </div>
              </div>
            </div>

            {activeTarget && (
              <span className="hidden sm:inline-block font-mono text-[11px] px-2 py-0.5 bg-[#f4f4f0] border border-[#d8d7d0] text-[#6b6a65] truncate max-w-[160px]">
                {activeTarget}
              </span>
            )}
          </div>

          {/* Messages Stream */}
          <div
            ref={logContainerRef}
            role="log"
            aria-live="polite"
            aria-relevant="additions"
            aria-label="История диалога с AI"
            className="cg-scroll-paper flex-1 overflow-y-auto px-4 py-4 space-y-3 bg-[#fbfbf9]"
          >
            <div className="flex justify-center">
              <span className="px-3 py-0.5 rounded-full bg-[#ecebe4] text-[#6b6a65] text-xs font-sans">
                Сегодня · 100% on-premise
              </span>
            </div>

            {messages.map((msg) => {
              const isUser = msg.role === 'user';
              const isStreaming = msg.id === 'streaming';
              return (
                <div
                  key={msg.id}
                  className={cn('flex', isUser ? 'justify-end' : 'justify-start')}
                >
                  <div
                    className={cn(
                      'max-w-[88%] px-4 py-2.5 flex flex-col gap-1',
                      isUser
                        ? 'bg-[#141414] text-[#faf9f5] rounded-[20px] rounded-br-[6px]'
                        : 'bg-[#e8e7e2] text-[#141414] rounded-[20px] rounded-bl-[6px]'
                    )}
                  >
                    <FormattedBubbleContent content={msg.content} isUser={isUser} />
                    <div
                      className={cn(
                        'font-mono text-[11px] tabular-nums flex items-center gap-1.5',
                        isUser ? 'justify-end text-[#a09d96]' : 'justify-start text-[#6b6a65]'
                      )}
                    >
                      <span>{msg.timestamp}</span>
                      {isStreaming && (
                        <span
                          className="inline-block w-1.5 h-3 bg-[#e94a32] animate-pulse"
                          aria-label="печатает"
                        />
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Starter Prompt Chips */}
          <div className="px-3.5 py-2 border-t border-[#ecebe4] bg-[#f7f7f4] grid grid-cols-1 sm:grid-cols-2 gap-1.5 shrink-0">
            {QUICK_PROMPTS.map((prompt) => (
              <button
                key={prompt}
                type="button"
                disabled={isTyping}
                onClick={() => onQuickPrompt(prompt)}
                className="text-left text-[11.5px] font-sans px-2.5 py-1 rounded-full border border-[#d8d7d0] bg-white hover:border-[#141414] text-[#3e3e3a] hover:text-[#141414] transition-colors cursor-pointer disabled:opacity-50 truncate"
              >
                {prompt}
              </button>
            ))}
          </div>

          {/* Rounded Pill Composer (matching prtner.ai chat mockup + IME-safe Enter submit) */}
          <div className="p-3 bg-white border-t border-[#ecebe4] shrink-0">
            <form
              ref={formRef}
              onSubmit={onSubmit}
              className="flex items-end gap-2 rounded-[24px] border border-[#d4d3cc] focus-within:border-[#141414] bg-white px-3 py-1.5 transition-colors"
            >
              <label htmlFor={inputId} className="visually-hidden">
                Сообщение для Commit Guardian AI или ссылка на GitHub
              </label>

              <input
                id={fileInputId}
                type="file"
                accept=".zip"
                className="visually-hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) onUploadZip(file);
                  e.target.value = '';
                }}
              />
              <button
                type="button"
                disabled={isScanning}
                onClick={() => document.getElementById(fileInputId)?.click()}
                aria-label="Прикрепить ZIP-архив кода"
                className="min-h-9 min-w-9 rounded-full hover:bg-[#f4f4f0] text-[#6b6a65] hover:text-[#141414] flex items-center justify-center shrink-0 transition-colors cursor-pointer disabled:opacity-50"
              >
                <Paperclip className="w-4 h-4" aria-hidden="true" />
              </button>

              <div className="cg-autogrow flex-1 min-w-0 py-1.5" data-replicated-value={input}>
                <textarea
                  id={inputId}
                  rows={1}
                  value={input}
                  onChange={(e) => onInputChange(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Спроси ИИ об уязвимости или вставь github.com/..."
                  className="bg-transparent text-[15px] text-[#141414] placeholder:text-[#6b6a65] focus:outline-none leading-[1.45]"
                />
              </div>

              <button
                type="submit"
                disabled={!input.trim() || isTyping}
                aria-label="Отправить сообщение"
                className="min-h-9 min-w-9 rounded-full bg-[#141414] hover:bg-[#e94a32] disabled:bg-[#c8c7bf] text-white flex items-center justify-center shrink-0 transition-colors cursor-pointer"
              >
                <Send className="w-4 h-4" aria-hidden="true" />
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* Specimen Meta Rows with Dotted Leaders (matching prtner.ai bottom of cards) */}
      <div className="px-5 pb-4 pt-1 space-y-1.5 font-mono text-xs text-[#6b6a65]">
        <div className="flex items-baseline gap-2">
          <span>Модель</span>
          <span className="spec-leader" aria-hidden="true" />
          <span className="text-[#141414] tabular-nums">{ollamaModel}</span>
        </div>
        <div className="flex items-baseline gap-2">
          <span>Ввод</span>
          <span className="spec-leader" aria-hidden="true" />
          <span className="text-[#141414]">Enter · Shift+Enter · ZIP</span>
        </div>
        <div className="flex items-baseline gap-2">
          <span>Утечка кода наружу</span>
          <span className="spec-leader" aria-hidden="true" />
          <span className="text-[#141414]">0 байт</span>
        </div>
      </div>

      {/* Drag & drop overlay */}
      {isDraggingZip && (
        <div className="absolute inset-0 bg-[#141414]/88 text-[#faf9f5] flex flex-col items-center justify-center gap-2 z-20 border-2 border-dashed border-[#e94a32]">
          <Upload className="w-7 h-7 text-[#e94a32]" aria-hidden="true" />
          <p className="font-mono text-sm">Отпусти .zip — проверю локально и удалю исходники</p>
        </div>
      )}
    </section>
  );
}
