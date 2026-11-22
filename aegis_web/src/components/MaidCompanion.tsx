'use client';

import { useEffect, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  FileText,
  HeartPulse,
  Lock,
  Pause,
  Play,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Upload,
  Zap,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export type CompanionMood = 'idle' | 'thinking' | 'scanning' | 'alert' | 'blocked' | 'happy';

interface MaidCompanionProps {
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
    src: string;
    alt: string;
    label: string;
    accentClass: string;
    ringColor: string;
    glowBg: string;
  }
> = {
  idle: {
    src: '/mascot/maid_idle.webp',
    alt: 'Aegis-chan — дежурный AI-компаньон безопасности кода',
    label: 'НА ДЕЖУРСТВЕ',
    accentClass: 'text-[#e94a32] border-[#e94a32]/35 bg-[#e94a32]/10',
    ringColor: 'border-[#e94a32]/30',
    glowBg: 'from-[#e94a32]/20 via-transparent to-transparent',
  },
  thinking: {
    src: '/mascot/maid_scan.webp',
    alt: 'Aegis-chan анализирует вопрос',
    label: 'ДУМАЮ…',
    accentClass: 'text-[#e8a33d] border-[#e8a33d]/40 bg-[#e8a33d]/10',
    ringColor: 'border-[#e8a33d]/45',
    glowBg: 'from-[#e8a33d]/22 via-transparent to-transparent',
  },
  scanning: {
    src: '/mascot/maid_scan.webp',
    alt: 'Aegis-chan сканирует коммиты и AST-граф',
    label: 'СКАНИРУЮ КОД',
    accentClass: 'text-sky-400 border-sky-400/45 bg-sky-400/12',
    ringColor: 'border-sky-400/55',
    glowBg: 'from-sky-400/24 via-[#e94a32]/12 to-transparent',
  },
  alert: {
    src: '/mascot/maid_alert.webp',
    alt: 'Aegis-chan обнаружила критические уязвимости',
    label: 'УГРОЗА НАЙДЕНА',
    accentClass: 'text-[#ff735d] border-[#e94a32]/55 bg-[#e94a32]/15',
    ringColor: 'border-[#e94a32]/70',
    glowBg: 'from-[#e94a32]/30 via-transparent to-transparent',
  },
  blocked: {
    src: '/mascot/maid_alert.webp',
    alt: 'Aegis-chan заблокировала чужой репозиторий без подтверждения авторства',
    label: 'ДОСТУП ЗАКРЫТ',
    accentClass: 'text-[#ff735d] border-[#e94a32]/55 bg-[#e94a32]/15',
    ringColor: 'border-[#e94a32]/65',
    glowBg: 'from-[#e94a32]/26 via-transparent to-transparent',
  },
  happy: {
    src: '/mascot/maid_happy.webp',
    alt: 'Aegis-chan радуется чистому или исцелённому коду',
    label: 'КОНТУР ЧИСТ',
    accentClass: 'text-[#3fbf7f] border-[#3fbf7f]/45 bg-[#3fbf7f]/12',
    ringColor: 'border-[#3fbf7f]/55',
    glowBg: 'from-[#3fbf7f]/25 via-transparent to-transparent',
  },
};

const POKE_LINES = [
  'Не отвлекай — я караулю твои коммиты, чтобы ни один ИИН и токен не утекли!',
  'Всё крутится локально on-prem: 0 байт исходников наружу, клянусь щитом.',
  'Нажми «Демо-аудит» — за 5 секунд покажу 17 багов и исцелю их в один клик.',
  'Чужой GitHub без `/verify` не пропущу — сначала докажи, что репо твоё.',
  'Можешь просто перетащить `.zip` прямо в чат — проверю и сразу сотру копию.',
];

export function MaidCompanion({
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
}: MaidCompanionProps) {
  const prefersReducedMotion = useReducedMotion();
  const [motionPaused, setMotionPaused] = useState(false);
  const [pokeIndex, setPokeIndex] = useState<number | null>(null);
  const [pokeCount, setPokeCount] = useState(0);

  // Preload all 4 mascot sprites once so mood transitions crossfade instantaneously
  useEffect(() => {
    ['/mascot/maid_idle.webp', '/mascot/maid_scan.webp', '/mascot/maid_alert.webp', '/mascot/maid_happy.webp'].forEach(
      (src) => {
        const img = new window.Image();
        img.src = src;
      }
    );
  }, []);

  const cfg = MOOD_CONFIG[mood];
  const disableMotion = Boolean(prefersReducedMotion || motionPaused);
  const activeSpeech = pokeIndex !== null ? POKE_LINES[pokeIndex] : speech;

  const handlePoke = () => {
    setPokeCount((c) => c + 1);
    setPokeIndex((prev) => (prev === null ? 0 : (prev + 1) % POKE_LINES.length));
  };

  return (
    <aside
      aria-label="Aegis-chan — живой AI-помощник"
      className={cn(
        'lg:h-full flex flex-col justify-between gap-3 p-4 sm:p-5 bg-[var(--color-paper)] border-b lg:border-b-0 lg:border-r border-[var(--color-line)] shrink-0',
        disableMotion && 'maid-paused'
      )}
    >
      {/* Top Companion Identity + Motion Pause Control (WCAG 2.2.2) */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={cn(
              'inline-flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-wider px-2.5 py-0.5 rounded-full border',
              cfg.accentClass
            )}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
            <span className="truncate">{cfg.label}</span>
          </span>
          {isScanning && (
            <span className="font-mono text-[11px] tabular-nums text-[var(--color-muted-soft)]">
              {elapsedTime.toFixed(1)}s
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={() => setMotionPaused((p) => !p)}
          title={motionPaused ? 'Включить анимацию питомца' : 'Поставить анимацию на паузу'}
          className="min-h-7 px-2 py-1 rounded-full border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] font-mono text-[10.5px] inline-flex items-center gap-1 transition-colors cursor-pointer shrink-0"
        >
          {motionPaused ? (
            <>
              <Play className="w-3 h-3" aria-hidden="true" />
              <span>Анимация</span>
            </>
          ) : (
            <>
              <Pause className="w-3 h-3" aria-hidden="true" />
              <span>Пауза</span>
            </>
          )}
        </button>
      </div>

      {/* Live Animated Maid-Guardian Portrait Stage */}
      <div className="flex flex-row lg:flex-col items-center gap-4 lg:gap-3.5 my-auto">
        <button
          type="button"
          onClick={handlePoke}
          aria-label="Погладить или спросить подсказку у Aegis-chan"
          className="group relative w-28 h-28 sm:w-36 sm:h-36 lg:w-60 lg:h-60 aspect-square shrink-0 rounded-3xl overflow-hidden border border-[var(--color-line-strong)] bg-[#0f0f12] shadow-[0_20px_44px_-22px_rgba(0,0,0,0.65)] cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#e94a32]"
        >
          {/* Ambient radial aura matching current mood */}
          <div
            aria-hidden="true"
            className={cn(
              'pointer-events-none absolute inset-0 bg-gradient-to-t opacity-90 transition-colors duration-500',
              cfg.glowBg
            )}
          />

          {/* Orbiting holographic security ring */}
          <div
            aria-hidden="true"
            className={cn(
              'pointer-events-none absolute inset-2.5 rounded-full border border-dashed transition-colors duration-300',
              cfg.ringColor,
              isScanning ? 'maid-orbit-fast' : 'maid-orbit'
            )}
          />

          {/* Crossfading animated sprite */}
          <motion.div
            key={`poke-${pokeCount}`}
            initial={disableMotion ? false : { scale: 0.96 }}
            animate={disableMotion ? { scale: 1 } : { scale: [0.96, 1.03, 1] }}
            transition={{ duration: 0.35, ease: 'easeOut' }}
            className={cn('relative w-full h-full flex items-center justify-center', !disableMotion && 'maid-float')}
          >
            <AnimatePresence mode="wait">
              <motion.img
                key={cfg.src}
                src={cfg.src}
                alt={cfg.alt}
                width={512}
                height={512}
                initial={disableMotion ? { opacity: 1 } : { opacity: 0, scale: 0.97 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={disableMotion ? { opacity: 0 } : { opacity: 0, scale: 1.02 }}
                transition={{ duration: 0.24 }}
                className="w-full h-full object-cover select-none"
                draggable={false}
              />
            </AnimatePresence>
          </motion.div>

          {/* Active scan laser sweep during scanning/thinking */}
          {(mood === 'scanning' || mood === 'thinking') && !disableMotion && (
            <div
              aria-hidden="true"
              className="maid-scanline pointer-events-none absolute inset-x-0 top-0 h-1/3 bg-gradient-to-b from-transparent via-sky-400/25 to-transparent border-b border-sky-400/60"
            />
          )}

          {/* Sparkles when happy */}
          {mood === 'happy' && !disableMotion && (
            <>
              <Sparkles
                aria-hidden="true"
                className="maid-sparkle pointer-events-none absolute top-3 right-3 w-4 h-4 text-[#3fbf7f]"
              />
              <Sparkles
                aria-hidden="true"
                className="maid-sparkle pointer-events-none absolute bottom-10 left-3 w-3.5 h-3.5 text-[#3fbf7f]"
              />
            </>
          )}

          {/* Bottom live nameplate overlay */}
          <div className="pointer-events-none absolute inset-x-0 bottom-0 px-3 py-1.5 bg-gradient-to-t from-[#09090b]/95 via-[#09090b]/70 to-transparent flex items-center justify-between gap-2">
            <span className="font-mono text-[11px] font-medium text-[#f4f4f2] tracking-tight">
              aegis-chan
            </span>
            {securityScore !== null && (
              <span
                className={cn(
                  'font-mono text-[10.5px] font-semibold tabular-nums px-1.5 py-0.5 rounded',
                  securityScore >= 70
                    ? 'bg-[#3fbf7f]/25 text-[#3fbf7f]'
                    : 'bg-[#e94a32]/25 text-[#ff735d]'
                )}
              >
                {securityScore}/100 {grade ?? ''}
              </span>
            )}
          </div>
        </button>

        {/* Companion Speech Bubble */}
        <div className="flex-1 lg:w-full min-w-0 space-y-2.5">
          <div className="relative rounded-2xl border border-[var(--color-line-strong)] bg-[var(--color-panel)] px-3.5 py-2.5 text-xs sm:text-[13px] leading-relaxed text-[var(--color-body-text)]">
            <div className="flex items-center justify-between gap-2 mb-1 font-mono text-[10px] uppercase tracking-wider text-[var(--color-muted-soft)]">
              <span>Aegis-chan · on-prem питомец</span>
              {pokeIndex !== null && (
                <button
                  type="button"
                  onClick={() => setPokeIndex(null)}
                  className="text-[#e94a32] hover:underline cursor-pointer"
                >
                  статус
                </button>
              )}
            </div>
            <AnimatePresence mode="wait">
              <motion.p
                key={activeSpeech}
                initial={disableMotion ? false : { opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={disableMotion ? undefined : { opacity: 0, y: -3 }}
                transition={{ duration: 0.18 }}
                className="text-[var(--color-ink)]"
              >
                {activeSpeech}
              </motion.p>
            </AnimatePresence>
          </div>

          {/* Primary 1-Click Companion Actions */}
          <div className="grid grid-cols-2 gap-1.5">
            <button
              type="button"
              disabled={isScanning}
              onClick={onDemoScan}
              className="min-h-9 px-3 py-1.5 rounded-xl bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white disabled:opacity-50 font-mono text-[11px] font-medium inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span>Демо-аудит</span>
            </button>

            {canSelfHeal ? (
              <button
                type="button"
                disabled={isHealing}
                onClick={onTriggerSelfHeal}
                className="min-h-9 px-3 py-1.5 rounded-xl bg-[#3fbf7f] hover:bg-[#34a96e] text-[#09120d] disabled:opacity-60 font-mono text-[11px] font-semibold inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                <HeartPulse className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                <span>{isHealing ? 'Лечу…' : 'Self-Heal'}</span>
              </button>
            ) : (
              <button
                type="button"
                disabled={isScanning}
                onClick={onUploadZipClick}
                className="min-h-9 px-3 py-1.5 rounded-xl border border-[var(--color-line-strong)] hover:border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-ink)] disabled:opacity-50 font-mono text-[11px] inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                <Upload className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                <span>Свой .zip</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Compact Module Shortcuts (open on-demand Inspector Drawer) */}
      <div className="grid grid-cols-4 lg:grid-cols-2 gap-1.5 pt-2 border-t border-[var(--color-line)] font-mono text-[11px]">
        <button
          type="button"
          onClick={() => onOpenDrawer('reports')}
          className="min-h-8 px-2.5 py-1.5 rounded-lg border border-[var(--color-line)] hover:border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 transition-colors cursor-pointer"
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
          className="min-h-8 px-2.5 py-1.5 rounded-lg border border-[var(--color-line)] hover:border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 transition-colors cursor-pointer"
        >
          <span className="inline-flex items-center gap-1 truncate">
            {findingsCount > 0 ? (
              <ShieldAlert className="w-3 h-3 text-[#ff735d] shrink-0" aria-hidden="true" />
            ) : (
              <ShieldCheck className="w-3 h-3 text-[#3fbf7f] shrink-0" aria-hidden="true" />
            )}
            <span className="truncate">Находки</span>
          </span>
          <span className="tabular-nums text-[var(--color-muted-soft)]">{findingsCount}</span>
        </button>

        <button
          type="button"
          onClick={() => onOpenDrawer('authorship')}
          className="min-h-8 px-2.5 py-1.5 rounded-lg border border-[var(--color-line)] hover:border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 transition-colors cursor-pointer"
        >
          <span className="inline-flex items-center gap-1 truncate">
            <Lock className="w-3 h-3 text-[#e8a33d] shrink-0" aria-hidden="true" />
            <span className="truncate">Авторство</span>
          </span>
          <span className={authorshipVerified ? 'text-[#3fbf7f]' : 'text-[#e8a33d]'}>
            {authorshipVerified ? 'OK' : 'LOCK'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => onOpenDrawer('scanner')}
          className="min-h-8 px-2.5 py-1.5 rounded-lg border border-[var(--color-line)] hover:border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-body-text)] hover:text-[var(--color-ink)] flex items-center justify-between gap-1.5 transition-colors cursor-pointer"
        >
          <span className="inline-flex items-center gap-1 truncate">
            <Terminal className="w-3 h-3 text-[var(--color-muted-soft)] shrink-0" aria-hidden="true" />
            <span className="truncate">Логи</span>
          </span>
          <span className="text-[var(--color-faint)]">live</span>
        </button>
      </div>
    </aside>
  );
}
