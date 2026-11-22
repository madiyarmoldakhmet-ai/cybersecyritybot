'use client';

import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import { Cloud, Cpu, Lock, RefreshCw, ShieldCheck, X } from 'lucide-react';

export interface AiEngineConfigStatus {
  provider: string;
  model: string;
  is_local: boolean;
  air_gapped: boolean;
  has_api_key: boolean;
  ollama_reachable: boolean;
  ollama_models: string[];
  recommended_local_model?: string;
  default_byok_models?: Record<string, string>;
}

interface AiModelSwitcherProps {
  onStatusChange?: (status: AiEngineConfigStatus) => void;
}

const BYOK_PROVIDERS = [
  { id: 'openrouter', label: 'OpenRouter', defaultModel: 'anthropic/claude-3.5-sonnet', hint: 'sk-or-v1-...' },
  { id: 'anthropic', label: 'Claude', defaultModel: 'claude-sonnet-4-20250514', hint: 'sk-ant-...' },
  { id: 'gemini', label: 'Gemini', defaultModel: 'gemini-2.5-flash', hint: 'AIza...' },
  { id: 'openai', label: 'OpenAI', defaultModel: 'gpt-4o-mini', hint: 'sk-...' },
] as const;

export function AiModelSwitcher({ onStatusChange }: AiModelSwitcherProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const baseId = useId();

  const [status, setStatus] = useState<AiEngineConfigStatus | null>(null);
  const [mode, setMode] = useState<'local' | 'byok'>('local');
  const [localModel, setLocalModel] = useState('qwen2.5-coder:7b');
  const [byokProvider, setByokProvider] = useState<string>('openrouter');
  const [byokModel, setByokModel] = useState<string>('anthropic/claude-3.5-sonnet');
  const [byokKey, setByokKey] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);

  const applyStatus = useCallback(
    (data: AiEngineConfigStatus) => {
      setStatus(data);
      onStatusChange?.(data);
      if (data.is_local) {
        setMode('local');
        if (data.model) setLocalModel(data.model);
      } else {
        setMode('byok');
        setByokProvider(data.provider);
        if (data.model) setByokModel(data.model);
      }
    },
    [onStatusChange]
  );

  const loadStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/ai/config', { cache: 'no-store' });
      if (!res.ok) return;
      const data: AiEngineConfigStatus = await res.json();
      applyStatus(data);
    } catch {
      // Ignore transient network failures during boot
    }
  }, [applyStatus]);

  useEffect(() => {
    let active = true;
    fetch('/api/ai/config', { cache: 'no-store' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data: AiEngineConfigStatus | null) => {
        if (active && data) applyStatus(data);
      })
      .catch(() => {
        // Ignore transient network failures during boot
      });
    return () => {
      active = false;
    };
  }, [applyStatus]);

  const openModal = () => {
    setError(null);
    setSavedNotice(null);
    void loadStatus();
    dialogRef.current?.showModal();
  };

  const closeModal = () => {
    dialogRef.current?.close();
    triggerRef.current?.focus();
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSavedNotice(null);
    setSaving(true);
    try {
      const payload =
        mode === 'local'
          ? { provider: 'ollama', model: localModel, reset: false }
          : {
              provider: byokProvider,
              model: byokModel.trim() || undefined,
              api_key: byokKey.trim() || undefined,
            };
      const res = await fetch('/api/ai/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || 'Не удалось переключить модель.');
        return;
      }
      setStatus(data);
      onStatusChange?.(data);
      setByokKey('');
      setSavedNotice(
        data.is_local
          ? `Активна локальная модель ${data.model} (0 байт в облако).`
          : `Подключён BYOK: ${data.provider} · ${data.model} (только в RAM).`
      );
    } catch {
      setError('Ошибка сети при обновлении AI-движка.');
    } finally {
      setSaving(false);
    }
  };

  const handleResetLocal = async () => {
    setError(null);
    setSavedNotice(null);
    setSaving(true);
    try {
      const res = await fetch('/api/ai/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'ollama', reset: true }),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus(data);
        onStatusChange?.(data);
        setMode('local');
        setLocalModel(data.model || 'qwen2.5-coder:7b');
        setByokKey('');
        setSavedNotice('Включён строгий локальный режим (Ollama · 0 байт в облако).');
      }
    } finally {
      setSaving(false);
    }
  };

  const isLocal = status ? status.is_local : true;
  const activeModel = status?.model || 'qwen2.5-coder:7b';
  const shortModel = activeModel.length > 22 ? `${activeModel.slice(0, 21)}…` : activeModel;
  const installedModels = status?.ollama_models?.length
    ? status.ollama_models
    : ['qwen2.5-coder:7b'];

  const activeByokMeta = BYOK_PROVIDERS.find((p) => p.id === byokProvider) || BYOK_PROVIDERS[0];

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        onClick={openModal}
        aria-haspopup="dialog"
        aria-label="Настройки AI-модели и режима приватности"
        className="hidden md:inline-flex items-center gap-1.5 font-mono text-[10.5px] px-2.5 py-1 rounded-full border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] transition-colors cursor-pointer"
      >
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            isLocal
              ? status?.ollama_reachable === false
                ? 'bg-amber-400'
                : 'bg-[#3fbf7f]'
              : 'bg-sky-400'
          }`}
          aria-hidden="true"
        />
        <span>
          {isLocal ? `on-prem · ${shortModel}` : `BYOK · ${status?.provider} · ${shortModel}`}
        </span>
      </button>

      <dialog
        ref={dialogRef}
        {...({ closedby: 'any' } as Record<string, string>)}
        onClick={(e) => {
          if (e.target === dialogRef.current) closeModal();
        }}
        aria-labelledby={`${baseId}-title`}
        className="m-auto w-[min(92vw,460px)] rounded-2xl border border-[var(--color-line-strong)] bg-[var(--color-paper)] text-[var(--color-ink)] p-0 shadow-2xl backdrop:bg-black/60 backdrop:backdrop-blur-xs"
      >
        <div className="px-4 py-3 border-b border-[var(--color-line)] flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Cpu className="w-4 h-4 text-[#e94a32] shrink-0" aria-hidden="true" />
            <h2 id={`${baseId}-title`} className="text-sm font-medium truncate">
              AI-движок аудита и авто-фикса
            </h2>
          </div>
          <button
            type="button"
            onClick={closeModal}
            aria-label="Закрыть настройки AI-модели"
            className="w-7 h-7 rounded-lg inline-flex items-center justify-center border border-[var(--color-line)] hover:border-[var(--color-line-strong)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] cursor-pointer"
          >
            <X className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSave} className="p-4 space-y-4">
          {/* Mode segmented buttons */}
          <div className="grid grid-cols-2 gap-1.5 p-1 rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)]">
            <button
              type="button"
              onClick={() => {
                setMode('local');
                setError(null);
              }}
              aria-pressed={mode === 'local'}
              className={`px-3 py-2 rounded-lg text-xs font-medium inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer ${
                mode === 'local'
                  ? 'bg-[var(--color-ink)] text-[var(--color-canvas)]'
                  : 'text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Локально (Ollama)</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('byok');
                setError(null);
              }}
              aria-pressed={mode === 'byok'}
              className={`px-3 py-2 rounded-lg text-xs font-medium inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer ${
                mode === 'byok'
                  ? 'bg-[var(--color-ink)] text-[var(--color-canvas)]'
                  : 'text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
              }`}
            >
              <Cloud className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Облако (BYOK)</span>
            </button>
          </div>

          {mode === 'local' ? (
            <div className="space-y-3">
              <div className="rounded-xl border border-[#3fbf7f]/30 bg-[#3fbf7f]/8 px-3 py-2.5 text-[11.5px] leading-relaxed">
                <span className="font-medium text-[#3fbf7f]">100% On-Premise:</span> 0 байт исходного
                кода уходит в облако. Используется локальная Ollama для Business-Logic аудита (IDOR/Auth/SSRF),
                чат-ассистента и LLM-автофикса.
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label htmlFor={`${baseId}-local-model`} className="font-mono text-[11px] text-[var(--color-muted-soft)]">
                    Локальная модель Ollama
                  </label>
                  <button
                    type="button"
                    onClick={() => void loadStatus()}
                    className="font-mono text-[10.5px] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] inline-flex items-center gap-1 cursor-pointer"
                  >
                    <RefreshCw className="w-3 h-3" aria-hidden="true" />
                    <span>Обновить</span>
                  </button>
                </div>
                <select
                  id={`${baseId}-local-model`}
                  value={localModel}
                  onChange={(e) => setLocalModel(e.target.value)}
                  className="w-full rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 font-mono text-xs text-[var(--color-ink)]"
                >
                  {installedModels.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
                <p className="font-mono text-[10.5px] text-[var(--color-muted-soft)]">
                  Статус Ollama:{' '}
                  {status?.ollama_reachable
                    ? `online (${installedModels.length} моделей)`
                    : 'standby (работает детерминистический SAST + структурный логик-аудитор)'}
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="rounded-xl border border-sky-500/30 bg-sky-500/8 px-3 py-2.5 text-[11.5px] leading-relaxed flex items-start gap-2">
                <Lock className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                <span>
                  Режим <strong>BYOK</strong> подключает Claude / GPT / Gemini / OpenRouter для максимальной
                  глубины поиска бизнес-логики. Ключ хранится <strong>только в RAM сервера</strong> до
                  перезапуска и никогда не пишется на диск.
                </span>
              </div>

              <div className="grid grid-cols-4 gap-1.5">
                {BYOK_PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => {
                      setByokProvider(p.id);
                      setByokModel(p.defaultModel);
                    }}
                    aria-pressed={byokProvider === p.id}
                    className={`px-2 py-1.5 rounded-lg border font-mono text-[10.5px] transition-colors cursor-pointer ${
                      byokProvider === p.id
                        ? 'border-[#e94a32] bg-[#e94a32]/12 text-[var(--color-ink)] font-medium'
                        : 'border-[var(--color-line)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>

              <div className="space-y-1">
                <label htmlFor={`${baseId}-byok-model`} className="font-mono text-[11px] text-[var(--color-muted-soft)]">
                  Модель
                </label>
                <input
                  id={`${baseId}-byok-model`}
                  type="text"
                  value={byokModel}
                  onChange={(e) => setByokModel(e.target.value)}
                  placeholder={activeByokMeta.defaultModel}
                  className="w-full rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 font-mono text-xs text-[var(--color-ink)]"
                />
              </div>

              <div className="space-y-1">
                <label htmlFor={`${baseId}-byok-key`} className="font-mono text-[11px] text-[var(--color-muted-soft)]">
                  API-ключ ({activeByokMeta.label})
                </label>
                <input
                  id={`${baseId}-byok-key`}
                  type="password"
                  autoComplete="new-password"
                  value={byokKey}
                  onChange={(e) => setByokKey(e.target.value)}
                  placeholder={
                    !isLocal && status?.provider === byokProvider && status?.has_api_key
                      ? '•••••••• (ключ уже активен в RAM)'
                      : activeByokMeta.hint
                  }
                  className="w-full rounded-xl border border-[var(--color-line)] bg-[var(--color-panel)] px-3 py-2 font-mono text-xs text-[var(--color-ink)]"
                />
              </div>
            </div>
          )}

          {error && (
            <p role="alert" className="text-xs text-[#e94a32] font-mono">
              ⛔ {error}
            </p>
          )}
          {savedNotice && (
            <p role="status" className="text-xs text-[#3fbf7f] font-mono">
              ✓ {savedNotice}
            </p>
          )}

          <div className="flex items-center justify-between gap-2 pt-1">
            {!isLocal ? (
              <button
                type="button"
                onClick={() => void handleResetLocal()}
                disabled={saving}
                className="px-3 py-2 rounded-xl border border-[var(--color-line)] hover:border-[var(--color-line-strong)] font-mono text-[11px] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] cursor-pointer"
              >
                Сбросить на On-Prem
              </button>
            ) : (
              <span className="font-mono text-[10.5px] text-[var(--color-muted-soft)]">
                12 сканеров + AI Logic + Auto-Fix
              </span>
            )}
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 rounded-xl bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white disabled:opacity-55 text-xs font-medium transition-colors cursor-pointer"
            >
              {saving ? 'Применяю…' : 'Применить'}
            </button>
          </div>
        </form>
      </dialog>
    </>
  );
}
