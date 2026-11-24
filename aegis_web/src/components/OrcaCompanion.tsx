'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useReducedMotion } from 'framer-motion';
import {
  FileText,
  HeartPulse,
  Lock,
  Pause,
  Play,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Upload,
  Volume2,
  VolumeX,
  Zap,
} from 'lucide-react';
import { PixelOrcaScene } from '@/components/PixelOrcaScene';
import { OrcaMood } from '@/components/OrcaRigSvg';
import { cn } from '@/lib/utils';

export type CompanionMood = OrcaMood;

interface OrcaCompanionProps {
  mood: CompanionMood;
  speech: string;
  isScanning: boolean;
  isHealing: boolean;
  elapsedTime: number;
  securityScore: number | null;
  grade: string | null;
  findingsCount: number;
  reportsCount: number;
  authorshipVerified: boolean;
  canSelfHeal: boolean;
  onDemoScan: () => void;
  onTriggerSelfHeal: () => void;
  onUploadZipClick: () => void;
  onOpenDrawer: (tab: 'reports' | 'findings' | 'scanner' | 'authorship') => void;
}

const MOOD_CONFIG: Record<
  CompanionMood,
  {
    label: string;
    accentClass: string;
    ringColor: string;
  }
> = {
  idle: {
    label: 'ПАТРУЛЬ',
    accentClass: 'text-[#56d4b2] border-[#2da890] bg-[#1f6e6c]/25',
    ringColor: 'border-[#2da890]',
  },
  thinking: {
    label: 'ДУМАЮ…',
    accentClass: 'text-[#ffe79e] border-[#f0b541] bg-[#f0b541]/20',
    ringColor: 'border-[#f0b541]',
  },
  scanning: {
    label: 'СОНАР-СКАН',
    accentClass: 'text-[#6ce4ff] border-[#2ca6c4] bg-[#2ca6c4]/20',
    ringColor: 'border-[#6ce4ff]',
  },
  alert: {
    label: 'УГРОЗА В КОДЕ',
    accentClass: 'text-[#ff7b66] border-[#e94a32] bg-[#e94a32]/20',
    ringColor: 'border-[#e94a32]',
  },
  blocked: {
    label: 'ЖДУ ПОДТВЕРЖДЕНИЯ',
    accentClass: 'text-[#ff7b66] border-[#e94a32] bg-[#e94a32]/20',
    ringColor: 'border-[#e94a32]',
  },
  happy: {
    label: 'ВОДА ЧИСТА',
    accentClass: 'text-[#5ee8a7] border-[#3fbf7f] bg-[#3fbf7f]/20',
    ringColor: 'border-[#47d18c]',
  },
};

const POKE_LINES = [
  'Привет! Пинг сонаром — ни один утёкший ИИН или секретный ключ не проплывёт мимо.',
  'Кинь ссылку на свой GitHub — я сама выдам кнопку подтверждения, проверю её и сразу запущу аудит!',
  'Жми «Демо-аудит» — за 5 секунд поймаю 17 багов и починю их кнопкой Self-Heal!',
  'Работаю 100% локально on-prem: ноль байт твоего кода уходит в облако.',
  'Нажми «Голос» наверху — я буду озвучивать всё голосом на русском и шевелить ртом в такт!',
];

const WIDE_VOWELS = /[аоуяэaou]/i;
const MID_VOWELS = /[еиыюёei]/i;
const PAUSE_CHARS = /[\s.,!?;:—–\-()]/;

function charToMouthLevel(ch: string): number {
  if (!ch || PAUSE_CHARS.test(ch)) return 0;
  if (WIDE_VOWELS.test(ch)) return 3;
  if (MID_VOWELS.test(ch)) return 2;
  return 1;
}

function cleanTextForTts(raw: string): string {
  return raw
    .replace(/[`*_#]/g, '')
    .replace(/https?:\/\/\S+/g, 'ссылку')
    .replace(/\s+/g, ' ')
    .trim();
}

export function OrcaCompanion({
  mood,
  speech,
  isScanning,
  isHealing,
  elapsedTime,
  securityScore,
  grade,
  findingsCount,
  reportsCount,
  authorshipVerified,
  canSelfHeal,
  onDemoScan,
  onTriggerSelfHeal,
  onUploadZipClick,
  onOpenDrawer,
}: OrcaCompanionProps) {
  const prefersReducedMotion = useReducedMotion();
  const [motionPaused, setMotionPaused] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(false);
  const [ttsSpeaking, setTtsSpeaking] = useState(false);
  const [pokeState, setPokeState] = useState<{ index: number; forSpeech: string } | null>(null);
  const [pokeCount, setPokeCount] = useState(0);

  // Live cursor eye-tracking normalized offset
  const stageRef = useRef<HTMLButtonElement | null>(null);
  const [lookOffset, setLookOffset] = useState<{ x: number; y: number }>({ x: 0.25, y: 0 });

  // Derived poke override (resets automatically without setState-in-effect when speech updates)
  const pokeIndex = pokeState && pokeState.forSpeech === speech ? pokeState.index : null;
  const activeSpeech = pokeIndex !== null ? POKE_LINES[pokeIndex] : speech;
  const speechKey = `${pokeCount}::${activeSpeech}`;

  // Typewriter speech stream + synchronized lip-sync state
  const [typeState, setTypeState] = useState<{ key: string; len: number; mouth: number }>({
    key: speechKey,
    len: 0,
    mouth: 0,
  });
  const [ttsMouth, setTtsMouth] = useState<number>(0);
  const lastSpokenRef = useRef<string>('');

  const disableMotion = Boolean(prefersReducedMotion || motionPaused);
  const typedLength = disableMotion
    ? activeSpeech.length
    : typeState.key === speechKey
    ? typeState.len
    : 0;
  const isTypewriting = !disableMotion && typedLength < activeSpeech.length;
  const isTalking = (isTypewriting || ttsSpeaking) && !disableMotion;
  const mouthLevel = disableMotion
    ? 0
    : isTypewriting
    ? typeState.key === speechKey
      ? typeState.mouth
      : 0
    : ttsSpeaking
    ? ttsMouth
    : 0;

  // Speak via Web Speech API (Russian TTS) with mouth lip-sync lifecycle
  const speakAloud = useCallback((text: string) => {
    if (typeof window === 'undefined' || !('speechSynthesis' in window)) return;
    const clean = cleanTextForTts(text);
    if (!clean) return;
    try {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance(clean);
      utterance.lang = 'ru-RU';
      utterance.rate = 1.06;
      utterance.pitch = 1.12;
      const voices = window.speechSynthesis.getVoices();
      const ruVoice =
        voices.find((v) => v.lang.toLowerCase().startsWith('ru') && /milena|google|yuri|katya|irina/i.test(v.name)) ||
        voices.find((v) => v.lang.toLowerCase().startsWith('ru'));
      if (ruVoice) utterance.voice = ruVoice;

      utterance.onstart = () => setTtsSpeaking(true);
      utterance.onend = () => {
        setTtsSpeaking(false);
        setTtsMouth(0);
      };
      utterance.onerror = () => {
        setTtsSpeaking(false);
        setTtsMouth(0);
      };
      utterance.onboundary = () => {
        setTtsMouth((prev) => (prev === 3 ? 1 : prev === 2 ? 3 : 2));
      };
      window.speechSynthesis.speak(utterance);
    } catch {
      setTtsSpeaking(false);
    }
  }, []);

  // Cancel TTS cleanly on unmount
  useEffect(() => {
    return () => {
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
    };
  }, []);

  // Typewriter streaming + vowel-driven lip-sync every time activeSpeech changes (only setState inside interval callback)
  useEffect(() => {
    if (disableMotion) return;

    let idx = 0;
    const stepMs = activeSpeech.length > 110 ? 18 : 24;
    const timer = setInterval(() => {
      idx += 1;
      if (idx >= activeSpeech.length) {
        setTypeState({ key: speechKey, len: activeSpeech.length, mouth: 0 });
        clearInterval(timer);
        return;
      }
      const ch = activeSpeech[idx - 1] || '';
      setTypeState({ key: speechKey, len: idx, mouth: charToMouthLevel(ch) });
    }, stepMs);

    return () => clearInterval(timer);
  }, [activeSpeech, speechKey, disableMotion]);

  // Keep mouth smoothly animating while Russian TTS continues after typewriter finishes
  useEffect(() => {
    if (!ttsSpeaking || isTypewriting || disableMotion) return;
    const pattern = [2, 3, 1, 2, 0, 3, 2, 1];
    let step = 0;
    const timer = setInterval(() => {
      setTtsMouth(pattern[step % pattern.length]);
      step += 1;
    }, 105);
    return () => {
      clearInterval(timer);
    };
  }, [ttsSpeaking, isTypewriting, disableMotion]);

  // Auto-speak new lines when user enabled Russian voice
  useEffect(() => {
    if (!voiceEnabled) return;
    if (lastSpokenRef.current === activeSpeech) return;
    lastSpokenRef.current = activeSpeech;
    speakAloud(activeSpeech);
  }, [voiceEnabled, activeSpeech, speakAloud]);

  // Cursor-tracking eye follow across the viewport (rAF throttled)
  useEffect(() => {
    if (disableMotion) return;
    let rafId = 0;
    const onPointerMove = (e: PointerEvent) => {
      if (rafId) return;
      rafId = window.requestAnimationFrame(() => {
        rafId = 0;
        const el = stageRef.current;
        if (!el) return;
        const rect = el.getBoundingClientRect();
        const cx = rect.left + rect.width * 0.65;
        const cy = rect.top + rect.height * 0.45;
        const nx = Math.max(-1, Math.min(1, (e.clientX - cx) / 360));
        const ny = Math.max(-1, Math.min(1, (e.clientY - cy) / 280));
        setLookOffset({ x: nx, y: ny });
      });
    };
    window.addEventListener('pointermove', onPointerMove, { passive: true });
    return () => {
      window.removeEventListener('pointermove', onPointerMove);
      if (rafId) window.cancelAnimationFrame(rafId);
    };
  }, [disableMotion]);

  const cfg = MOOD_CONFIG[mood];
  const visibleSpeech = activeSpeech.slice(0, typedLength);

  const handleToggleVoice = () => {
    if (voiceEnabled) {
      setVoiceEnabled(false);
      setTtsSpeaking(false);
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
      return;
    }
    setVoiceEnabled(true);
    lastSpokenRef.current = activeSpeech;
    speakAloud(activeSpeech);
  };

  const handlePoke = () => {
    const nextIdx = pokeIndex === null ? 0 : (pokeIndex + 1) % POKE_LINES.length;
    setPokeCount((c) => c + 1);
    setPokeState({ index: nextIdx, forSpeech: speech });
    if (voiceEnabled) {
      lastSpokenRef.current = POKE_LINES[nextIdx];
      speakAloud(POKE_LINES[nextIdx]);
    }
  };

  return (
    <aside
      aria-label="Aegis Orca — живая говорящая пиксельная косатка-помощник"
      className={cn(
        'lg:h-full flex flex-col justify-between gap-3 p-4 sm:p-5 bg-[var(--color-paper)] border-b-2 lg:border-b-0 lg:border-r-2 border-[var(--color-line)] shrink-0',
        disableMotion && 'orca-paused'
      )}
    >
      {/* Top Companion Status + Voice + Motion Pause Controls */}
      <div className="flex items-center justify-between gap-1.5">
        <div className="flex items-center gap-1.5 min-w-0">
          <span
            className={cn(
              'inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider px-2 py-0.5 border-2 shadow-[2px_2px_0_var(--pixel-shadow)]',
              cfg.accentClass
            )}
          >
            <span className="w-2 h-2 bg-current shrink-0" aria-hidden="true" />
            <span className="truncate">{cfg.label}</span>
          </span>
          {isScanning && (
            <span className="font-mono text-[11px] tabular-nums text-[var(--color-muted-soft)]">
              {elapsedTime.toFixed(1)}s
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={handleToggleVoice}
            title={voiceEnabled ? 'Выключить озвучку косатки' : 'Включить русский голос косатки'}
            className={cn(
              'pixel-btn min-h-7 px-2 py-1 font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer',
              voiceEnabled
                ? '!border-[#47d18c] bg-[#47d18c]/20 text-[#5ee8a7]'
                : 'bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
            )}
          >
            {voiceEnabled ? (
              <>
                <Volume2 className="w-3 h-3" aria-hidden="true" />
                <span>Голос</span>
              </>
            ) : (
              <>
                <VolumeX className="w-3 h-3" aria-hidden="true" />
                <span>Тихо</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => setMotionPaused((p) => !p)}
            title={motionPaused ? 'Включить анимацию косатки' : 'Поставить анимацию на паузу'}
            className="pixel-btn min-h-7 px-2 py-1 bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer"
          >
            {motionPaused ? (
              <>
                <Play className="w-3 h-3" aria-hidden="true" />
                <span className="sr-only sm:not-sr-only">Старт</span>
              </>
            ) : (
              <>
                <Pause className="w-3 h-3" aria-hidden="true" />
                <span className="sr-only sm:not-sr-only">Пауза</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Live 16-Bit Pixel-Art Aurora & Orca Stage (Ultra-Lightweight 2D Canvas) */}
      <div className="flex flex-row lg:flex-col items-center gap-3.5 my-auto">
        <button
          ref={stageRef}
          type="button"
          onClick={handlePoke}
          aria-label="Кликнуть по пиксельной косатке Aegis Orca, чтобы она заговорила"
          className={cn(
            'group relative w-28 h-28 sm:w-36 sm:h-36 lg:w-full lg:h-[246px] shrink-0 overflow-hidden border-2 bg-[#0b0e18] shadow-[4px_4px_0_var(--pixel-shadow)] cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ffe79e] transition-colors',
            cfg.ringColor
          )}
        >
          <div className="relative w-full h-full">
            <PixelOrcaScene
              mood={mood}
              isTalking={isTalking}
              mouthLevel={mouthLevel}
              paused={disableMotion}
              lookX={lookOffset.x}
              lookY={lookOffset.y}
              pokeTrigger={pokeCount}
            />
          </div>

          {/* Crisp 16-bit Pixel Frame Nameplate + Talking Equalizer Bars */}
          <div className="pointer-events-none absolute inset-x-0 bottom-0 px-2.5 py-1.5 bg-[#0b0e18]/90 border-t-2 border-[#2a3b61] flex items-center justify-between gap-2 z-20">
            <div className="flex items-center gap-2">
              <span className="font-pixel text-[9px] text-[#eef6ff] tracking-wide">
                aegis.orca
              </span>
              {isTalking && (
                <span className="inline-flex items-end gap-[2px] h-3" aria-label="говорит">
                  <span className="orca-eq-bar w-[3px] h-full bg-[#56d4b2]" style={{ animationDelay: '0ms' }} />
                  <span className="orca-eq-bar w-[3px] h-full bg-[#ffe79e]" style={{ animationDelay: '120ms' }} />
                  <span className="orca-eq-bar w-[3px] h-full bg-[#e94a32]" style={{ animationDelay: '220ms' }} />
                  <span className="orca-eq-bar w-[3px] h-full bg-[#56d4b2]" style={{ animationDelay: '70ms' }} />
                </span>
              )}
            </div>

            {securityScore !== null && (
              <span
                className={cn(
                  'hidden sm:inline-block font-mono text-[11px] font-semibold tabular-nums px-1.5 py-0.5 border',
                  securityScore >= 70
                    ? 'bg-[#3fbf7f]/25 text-[#5ee8a7] border-[#47d18c]'
                    : 'bg-[#e94a32]/25 text-[#ff8573] border-[#e94a32]'
                )}
              >
                {securityScore}/100 {grade ?? ''}
              </span>
            )}
          </div>
        </button>

        {/* Live Talking RPG Pixel Dialogue Box (Typewriter + Instant Speak Replay) */}
        <div className="flex-1 lg:w-full min-w-0 space-y-2.5">
          <div className="pixel-card relative bg-[var(--color-panel)] px-3.5 py-2.5 text-[13px] leading-relaxed text-[var(--color-body-text)]">
            <div className="flex items-center justify-between gap-2 mb-1 font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)] whitespace-nowrap">
              <span className="inline-flex items-center gap-1 min-w-0 truncate">
                <span className="text-[var(--color-aurora)]">▸</span>
                <span className="hidden sm:inline">Aegis</span>
                <span>Orca</span>
                {isTalking && (
                  <span className="text-[var(--color-aurora)] normal-case truncate">· говорит…</span>
                )}
              </span>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => speakAloud(activeSpeech)}
                  title="Озвучить фразу голосом"
                  className="text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] inline-flex items-center gap-0.5 cursor-pointer"
                >
                  <Volume2 className="w-3 h-3" aria-hidden="true" />
                  <span>сказать</span>
                </button>
                {pokeIndex !== null && (
                  <button
                    type="button"
                    onClick={() => setPokeState(null)}
                    className="text-[#e94a32] hover:underline cursor-pointer"
                  >
                    статус
                  </button>
                )}
              </div>
            </div>
            <p className="text-[var(--color-ink)] min-h-[2.6em]">
              {visibleSpeech}
              {isTypewriting && (
                <span
                  aria-hidden="true"
                  className="pixel-blink inline-block w-2 h-3.5 ml-0.5 align-middle bg-[#56d4b2]"
                />
              )}
            </p>
          </div>

          {/* Primary 1-Click Pixel Actions */}
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              disabled={isScanning}
              onClick={onDemoScan}
              className="pixel-btn-snow min-h-9 px-3 py-1.5 disabled:opacity-50 font-mono text-[12px] font-semibold inline-flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span>Демо-аудит</span>
            </button>

            {canSelfHeal ? (
              <button
                type="button"
                disabled={isHealing}
                onClick={onTriggerSelfHeal}
                className="pixel-btn-emerald min-h-9 px-3 py-1.5 disabled:opacity-60 font-mono text-[12px] font-semibold inline-flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <HeartPulse className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                <span>{isHealing ? 'Лечу…' : 'Self-Heal'}</span>
              </button>
            ) : (
              <button
                type="button"
                disabled={isScanning}
                onClick={onUploadZipClick}
                className="pixel-btn min-h-9 px-3 py-1.5 bg-[var(--color-panel)] text-[var(--color-ink)] disabled:opacity-50 font-mono text-[12px] inline-flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Upload className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                <span>Свой .zip</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Compact Pixel Module Shortcuts */}
      <div className="grid grid-cols-2 gap-2 pt-2.5 border-t-2 border-[var(--color-line)] font-mono text-[12px]">
        <button
          type="button"
          onClick={() => onOpenDrawer('reports')}
          className="pixel-btn min-h-8 px-2.5 py-1.5 bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 cursor-pointer"
        >
          <span className="inline-flex items-center gap-1 truncate">
            <FileText className="w-3 h-3 text-[#e94a32] shrink-0" aria-hidden="true" />
            <span className="truncate">Отчёты</span>
          </span>
          <span className="tabular-nums text-[var(--color-muted-soft)]">{reportsCount}</span>
        </button>

        <button
          type="button"
          onClick={() => onOpenDrawer('findings')}
          className="pixel-btn min-h-8 px-2.5 py-1.5 bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 cursor-pointer"
        >
          <span className="inline-flex items-center gap-1 truncate">
            {findingsCount > 0 ? (
              <ShieldAlert className="w-3 h-3 text-[#ff7b66] shrink-0" aria-hidden="true" />
            ) : (
              <ShieldCheck className="w-3 h-3 text-[#47d18c] shrink-0" aria-hidden="true" />
            )}
            <span className="truncate">Находки</span>
          </span>
          <span className="tabular-nums text-[var(--color-muted-soft)]">{findingsCount}</span>
        </button>

        <button
          type="button"
          onClick={() => onOpenDrawer('authorship')}
          className="pixel-btn min-h-8 px-2.5 py-1.5 bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 cursor-pointer"
        >
          <span className="inline-flex items-center gap-1 truncate">
            <Lock className="w-3 h-3 text-[#f0b541] shrink-0" aria-hidden="true" />
            <span className="truncate">Авторство</span>
          </span>
          <span className={authorshipVerified ? 'text-[#47d18c]' : 'text-[#f0b541]'}>
            {authorshipVerified ? 'OK' : 'LOCK'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => onOpenDrawer('scanner')}
          className="pixel-btn min-h-8 px-2.5 py-1.5 bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 cursor-pointer"
        >
          <span className="inline-flex items-center gap-1 truncate">
            <Terminal className="w-3 h-3 text-[var(--color-aurora)] shrink-0" aria-hidden="true" />
            <span className="truncate">Логи</span>
          </span>
          <span className="text-[var(--color-aurora)]">live</span>
        </button>
      </div>
    </aside>
  );
}
