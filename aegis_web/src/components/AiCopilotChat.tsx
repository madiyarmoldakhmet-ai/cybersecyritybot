'use client';

import { FormEvent, KeyboardEvent, ReactNode, useEffect, useId, useRef, useState } from 'react';
import { ArrowUp, Paperclip, RotateCcw, Upload } from 'lucide-react';
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
  'Как работает проверка авторства?',
];

function renderInlineFormatting(line: string, keyPrefix: string): ReactNode[] {
  const tokens = line.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return tokens.map((token, idx) => {
    if (token.startsWith('`') && token.endsWith('`') && token.length >= 2) {
      return (
        <code
          key={`${keyPrefix}-${idx}`}
          className="font-mono text-[0.86em] px-1.5 py-0.5 rounded bg-[var(--color-canvas)] border border-[var(--color-line)] text-[var(--color-ink)] break-words"
        >
          {token.slice(1, -1)}
        </code>
      );
    }
    if (token.startsWith('**') && token.endsWith('**') && token.length >= 4) {
      return (
        <strong key={`${keyPrefix}-${idx}`} className="font-semibold text-[var(--color-ink)]">
          {token.slice(2, -2)}
        </strong>
      );
    }
    return <span key={`${keyPrefix}-${idx}`}>{token}</span>;
  });
}

function FormattedBubbleContent({ content }: { content: string }) {
  const segments = content.split(/(```[\s\S]*?```)/g);

  return (
    <div className="space-y-2 text-[14.5px] leading-[1.55] break-words [overflow-wrap:anywhere]">
      {segments.map((segment, segIdx) => {
        if (segment.startsWith('```') && segment.endsWith('```') && segment.length >= 6) {
          const inner = segment.slice(3, -3).replace(/^[a-zA-Z0-9_-]+\n/, '');
          return (
            <pre
              key={`code-${segIdx}`}
              className="font-mono text-xs p-3 rounded-lg overflow-x-auto bg-[#0a0a0a] border border-[#232323] text-[#d9f99d]"
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
      aria-label="AI-ассистент безопасности"
      className={cn(
        'bg-[var(--color-paper)] text-[var(--color-ink)] flex flex-col relative min-h-[520px] max-h-[680px]',
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
      {/* Minimal Header echoing prtner card bar */}
      <div className="px-5 py-3.5 border-b border-[var(--color-line)] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          {/* Geometric 2x2 mark */}
          <div className="grid grid-cols-2 gap-0.5 w-3.5 h-3.5 shrink-0" aria-hidden="true">
            <span className="bg-[#e94a32]" />
            <span className="bg-[var(--color-ink)]" />
            <span className="bg-[var(--color-ink)]" />
            <span className="bg-[var(--color-ink)] opacity-45" />
          </div>
          <span className="font-sans text-sm font-medium tracking-tight truncate">
            commit.guardian
          </span>
          <span className="hidden sm:inline-flex items-center gap-1.5 font-mono text-[11px] text-[var(--color-muted-soft)]">
            <span
              className={cn(
                'w-1.5 h-1.5 rounded-full',
                ollamaOnline ? 'bg-[#3fbf7f]' : 'bg-[#e8a33d]'
              )}
              aria-hidden="true"
            />
            {ollamaOnline ? `online · ${ollamaModel}` : `appsec-engine · standby`}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {activeTarget && (
            <span className="hidden md:inline-block font-mono text-[11px] px-2 py-0.5 rounded bg-[var(--color-panel)] border border-[var(--color-line)] text-[var(--color-muted-soft)] truncate max-w-[160px]">
              {activeTarget}
            </span>
          )}
          <button
            type="button"
            onClick={onResetChat}
            className="min-h-8 px-2.5 py-1 rounded-full border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[11px] inline-flex items-center gap-1 transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3 h-3" aria-hidden="true" />
            <span>Новый чат</span>
          </button>
        </div>
      </div>

      {/* Message Stream */}
      <div
        ref={logContainerRef}
        role="log"
        aria-live="polite"
        aria-relevant="additions"
        aria-label="Переписка с локальным AI-ассистентом"
        className="cg-scroll flex-1 overflow-y-auto px-5 py-4 space-y-3.5"
      >
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
                  'max-w-[90%] sm:max-w-[82%] px-4 py-3 flex flex-col gap-1.5 border',
                  isUser
                    ? 'bg-[var(--color-raised)] border-[var(--color-line-strong)] text-[var(--color-ink)] rounded-2xl rounded-br-sm'
                    : 'bg-[var(--color-panel)] border-[var(--color-line)] text-[var(--color-body-text)] rounded-2xl rounded-bl-sm'
                )}
              >
                <FormattedBubbleContent content={msg.content} />
                <div
                  className={cn(
                    'font-mono text-[10.5px] tabular-nums flex items-center gap-1.5 text-[var(--color-faint)]',
                    isUser ? 'justify-end' : 'justify-start'
                  )}
                >
                  <span>{isUser ? 'you' : 'ai'} · {msg.timestamp}</span>
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

      {/* Minimal Prompt Chips */}
      <div className="px-5 py-2 border-t border-[var(--color-line)] flex flex-wrap gap-1.5 shrink-0 bg-[var(--color-paper)]">
        {QUICK_PROMPTS.map((prompt) => (
          <button
            key={prompt}
            type="button"
            disabled={isTyping}
            onClick={() => onQuickPrompt(prompt)}
            className="text-xs font-sans px-3 py-1 rounded-full border border-[var(--color-line)] bg-[var(--color-panel)] hover:border-[#e94a32] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] transition-colors cursor-pointer disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Sleek Dark Pill Composer */}
      <div className="p-4 border-t border-[var(--color-line)] shrink-0 bg-[var(--color-paper)]">
        <form
          ref={formRef}
          onSubmit={onSubmit}
          className="flex items-end gap-2 rounded-2xl border border-[var(--color-line-strong)] focus-within:border-[#e94a32] bg-[var(--color-panel)] px-3 py-1.5 transition-colors"
        >
          <label htmlFor={inputId} className="visually-hidden">
            Сообщение для AI-ассистента или ссылка на GitHub
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
            aria-label="Загрузить ZIP-архив кода"
            className="min-h-9 min-w-9 rounded-full hover:bg-[var(--color-raised)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] flex items-center justify-center shrink-0 transition-colors cursor-pointer disabled:opacity-50"
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
              placeholder="Спроси AI о коде или вставь github.com/owner/repo..."
              className="bg-transparent text-[15px] text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none leading-[1.45]"
            />
          </div>

          <button
            type="submit"
            disabled={!input.trim() || isTyping}
            aria-label="Отправить сообщение"
            className="min-h-9 min-w-9 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] disabled:opacity-35 text-[var(--color-canvas)] hover:text-white flex items-center justify-center shrink-0 transition-colors cursor-pointer"
          >
            <ArrowUp className="w-4 h-4" aria-hidden="true" />
          </button>
        </form>
      </div>

      {isDraggingZip && (
        <div className="absolute inset-0 bg-[var(--color-canvas)]/92 text-[var(--color-ink)] flex flex-col items-center justify-center gap-2 z-20 border-2 border-dashed border-[#e94a32]">
          <Upload className="w-7 h-7 text-[#e94a32]" aria-hidden="true" />
          <p className="font-mono text-sm">Отпусти .zip — проверю локально и удалю исходники</p>
        </div>
      )}
    </section>
  );
}
