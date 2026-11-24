'use client';

import { useEffect, useId, useState } from 'react';
import { cn } from '@/lib/utils';

export type OrcaMood = 'idle' | 'thinking' | 'scanning' | 'alert' | 'blocked' | 'happy';

interface OrcaRigSvgProps {
  mood: OrcaMood;
  isTalking: boolean;
  /** 0 = closed, 1 = slight open, 2 = medium open, 3 = wide open */
  mouthLevel: number;
  paused?: boolean;
  /** Normalized cursor offset in [-1, 1] for live eye & head tracking */
  lookX?: number;
  lookY?: number;
  className?: string;
}

const MOOD_PALETTE: Record<
  OrcaMood,
  {
    accent: string;
    accentSoft: string;
    irisTop: string;
    irisBottom: string;
    backdrop: string;
  }
> = {
  idle: {
    accent: '#38bdf8',
    accentSoft: 'rgba(56, 189, 248, 0.22)',
    irisTop: '#7dd3fc',
    irisBottom: '#0284c7',
    backdrop: '#0b1829',
  },
  thinking: {
    accent: '#f59e0b',
    accentSoft: 'rgba(245, 158, 11, 0.24)',
    irisTop: '#fde68a',
    irisBottom: '#d97706',
    backdrop: '#1f1609',
  },
  scanning: {
    accent: '#38bdf8',
    accentSoft: 'rgba(56, 189, 248, 0.28)',
    irisTop: '#bae6fd',
    irisBottom: '#0ea5e9',
    backdrop: '#071b2d',
  },
  alert: {
    accent: '#ff5a3c',
    accentSoft: 'rgba(233, 74, 50, 0.28)',
    irisTop: '#fca5a5',
    irisBottom: '#dc2626',
    backdrop: '#240c0c',
  },
  blocked: {
    accent: '#e94a32',
    accentSoft: 'rgba(233, 74, 50, 0.26)',
    irisTop: '#fda4af',
    irisBottom: '#b91c1c',
    backdrop: '#220b0c',
  },
  happy: {
    accent: '#3fbf7f',
    accentSoft: 'rgba(63, 191, 127, 0.26)',
    irisTop: '#86efac',
    irisBottom: '#16a34a',
    backdrop: '#091f17',
  },
};

export function OrcaRigSvg({
  mood,
  isTalking,
  mouthLevel,
  paused = false,
  lookX = 0,
  lookY = 0,
  className,
}: OrcaRigSvgProps) {
  const uid = useId().replace(/:/g, '');
  const [isBlinking, setIsBlinking] = useState(false);

  // Autonomous natural eyelid blinking (every 2.6–5.2s, occasional quick double-blink)
  useEffect(() => {
    if (paused) return;
    let openTimer: ReturnType<typeof setTimeout> | null = null;
    let nextTimer: ReturnType<typeof setTimeout> | null = null;
    let active = true;

    const scheduleBlink = () => {
      const waitMs = 2600 + Math.floor(Math.random() * 2600);
      nextTimer = setTimeout(() => {
        if (!active) return;
        setIsBlinking(true);
        openTimer = setTimeout(() => {
          if (!active) return;
          setIsBlinking(false);
          // 22% chance of cute double-blink
          if (Math.random() < 0.22) {
            nextTimer = setTimeout(() => {
              if (!active) return;
              setIsBlinking(true);
              openTimer = setTimeout(() => {
                if (!active) return;
                setIsBlinking(false);
                scheduleBlink();
              }, 115);
            }, 130);
          } else {
            scheduleBlink();
          }
        }, 135);
      }, waitMs);
    };

    scheduleBlink();
    return () => {
      active = false;
      if (openTimer) clearTimeout(openTimer);
      if (nextTimer) clearTimeout(nextTimer);
    };
  }, [paused]);

  const pal = MOOD_PALETTE[mood];
  const fastTail = mood === 'scanning' || mood === 'happy' || isTalking;
  const angry = mood === 'alert' || mood === 'blocked';
  const scanning = mood === 'scanning' || mood === 'thinking';
  const happy = mood === 'happy';

  // Clamp pupil + micro-face tracking cleanly
  const px = paused ? 0 : Math.max(-1, Math.min(1, lookX)) * 3.4;
  const py = paused ? 0 : Math.max(-1, Math.min(1, lookY)) * 2.6;
  const headShiftX = paused ? 0 : Math.max(-1, Math.min(1, lookX)) * 1.8;
  const headShiftY = paused ? 0 : Math.max(-1, Math.min(1, lookY)) * 1.3;

  const activeMouth = isTalking ? Math.max(0, Math.min(3, mouthLevel)) : 0;

  return (
    <svg
      viewBox="0 0 260 260"
      role="img"
      aria-label="Aegis Orca — анимированная косатка-помощник"
      className={cn('w-full h-full select-none', className)}
    >
      <defs>
        <radialGradient id={`${uid}-bg`} cx="52%" cy="48%" r="58%">
          <stop offset="0%" stopColor={pal.backdrop} />
          <stop offset="68%" stopColor="#090c14" />
          <stop offset="100%" stopColor="#05070c" />
        </radialGradient>

        <linearGradient id={`${uid}-skin`} x1="25%" y1="10%" x2="78%" y2="92%">
          <stop offset="0%" stopColor="#26344b" />
          <stop offset="36%" stopColor="#121a2a" />
          <stop offset="78%" stopColor="#080d17" />
          <stop offset="100%" stopColor="#04070e" />
        </linearGradient>

        <linearGradient id={`${uid}-skin-fin`} x1="15%" y1="0%" x2="85%" y2="100%">
          <stop offset="0%" stopColor="#2c3d58" />
          <stop offset="50%" stopColor="#111927" />
          <stop offset="100%" stopColor="#060911" />
        </linearGradient>

        <linearGradient id={`${uid}-belly`} x1="40%" y1="0%" x2="60%" y2="100%">
          <stop offset="0%" stopColor="#ffffff" />
          <stop offset="68%" stopColor="#eef6ff" />
          <stop offset="100%" stopColor="#cbd5e1" />
        </linearGradient>

        <linearGradient id={`${uid}-rim`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#e0f2fe" stopOpacity="0.65" />
          <stop offset="55%" stopColor={pal.accent} stopOpacity="0.45" />
          <stop offset="100%" stopColor={pal.accent} stopOpacity="0" />
        </linearGradient>

        <linearGradient id={`${uid}-iris`} x1="50%" y1="0%" x2="50%" y2="100%">
          <stop offset="0%" stopColor={pal.irisTop} />
          <stop offset="100%" stopColor={pal.irisBottom} />
        </linearGradient>

        <linearGradient id={`${uid}-visor`} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor={pal.accent} stopOpacity="0.14" />
          <stop offset="50%" stopColor={pal.accent} stopOpacity="0.42" />
          <stop offset="100%" stopColor={pal.accent} stopOpacity="0.16" />
        </linearGradient>

        <filter id={`${uid}-glow`} x="-35%" y="-35%" width="170%" height="170%">
          <feGaussianBlur stdDeviation="3.2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Deep Cyber-Ocean Stage Backdrop */}
      <rect x="0" y="0" width="260" height="260" fill={`url(#${uid}-bg)`} />

      {/* Subtle Underwater Sonar Reticle */}
      <g opacity="0.24" stroke={pal.accent} fill="none">
        <circle cx="136" cy="134" r="96" strokeWidth="0.75" strokeDasharray="3 6" />
        <circle cx="136" cy="134" r="68" strokeWidth="0.6" strokeDasharray="2 5" />
        <line x1="18" y1="134" x2="242" y2="134" strokeWidth="0.45" opacity="0.45" />
        <line x1="136" y1="22" x2="136" y2="242" strokeWidth="0.45" opacity="0.45" />
      </g>

      {/* Soft Underbody Ocean Shadow */}
      <ellipse cx="138" cy="212" rx="68" ry="12" fill="#020617" opacity="0.65" />

      {/* === ARTICULATED ORCA SKELETON ROOT === */}
      <g className={cn(!paused && 'orca-swim')}>
        {/* 1. ARTICULATED TAIL PEDUNCLE + CRESCENT FLUKES (pivot 82, 150) */}
        <g className={cn(!paused && (fastTail ? 'orca-tail-bone-fast' : 'orca-tail-bone'))}>
          <path
            d="M 88 136
               C 70 144, 52 152, 39 158
               C 31 140, 22 126, 14 123
               C 21 139, 25 153, 27 162
               C 22 172, 23 189, 32 203
               C 38 190, 46 177, 56 171
               C 68 167, 79 166, 92 162 Z"
            fill={`url(#${uid}-skin-fin)`}
            stroke="#1e293b"
            strokeWidth="1.2"
            strokeLinejoin="round"
          />
          {/* Glossy fluke edge highlight */}
          <path
            d="M 20 128 C 28 140, 34 152, 41 159"
            fill="none"
            stroke={pal.accent}
            strokeWidth="1.4"
            strokeLinecap="round"
            opacity="0.65"
          />
        </g>

        {/* 2. FAR-SIDE PECTORAL FIN (behind belly for depth, pivot 174, 154) */}
        <g className={cn(!paused && 'orca-fin-back-bone')}>
          <path
            d="M 168 152 C 185 164, 198 184, 184 192 C 171 196, 160 176, 156 160 Z"
            fill="#070b14"
            stroke="#1e293b"
            strokeWidth="1"
          />
        </g>

        {/* 3. TALL ICONIC DORSAL FIN + CYBER LED STRIP (pivot 112, 92) */}
        <g className={cn(!paused && 'orca-dorsal-bone')}>
          <path
            d="M 94 98
               C 90 73, 76 47, 67 34
               C 85 40, 108 58, 126 86 Z"
            fill={`url(#${uid}-skin-fin)`}
            stroke="#1e293b"
            strokeWidth="1.2"
            strokeLinejoin="round"
          />
          {/* Glowing Cyber-Guardian LED edge along dorsal fin */}
          <path
            d="M 73 41 C 85 52, 96 68, 105 85"
            fill="none"
            stroke={pal.accent}
            strokeWidth="2.4"
            strokeLinecap="round"
            filter={`url(#${uid}-glow)`}
          />
        </g>

        {/* 4. MAIN SLEEK TORPEDO BODY & HEAD */}
        <g>
          {/* Main Obsidian Torso & Rounded Melon Head */}
          <path
            d="M 76 146
               C 74 114, 96 82, 134 75
               C 166 69, 198 83, 214 109
               C 223 123, 224 136, 216 146
               C 206 159, 185 170, 156 177
               C 126 184, 96 178, 76 162 Z"
            fill={`url(#${uid}-skin)`}
            stroke="#24334b"
            strokeWidth="1.35"
          />

          {/* Classic Smoky Silver Saddle Patch behind Dorsal Fin */}
          <path
            d="M 88 112 C 98 99, 114 94, 122 100 C 114 111, 106 123, 94 128 C 88 124, 86 118, 88 112 Z"
            fill="#64748b"
            opacity="0.34"
          />

          {/* Iconic Snow-White Orca Belly + Flank Flare */}
          <path
            d="M 213 144
               C 203 158, 183 169, 156 176
               C 127 183, 101 178, 84 166
               C 90 155, 101 146, 115 144
               C 108 153, 109 162, 121 164
               C 143 166, 174 159, 198 148
               C 205 145, 210 143, 213 144 Z"
            fill={`url(#${uid}-belly)`}
          />

          {/* Volumetric Gloss Rim Highlight along Forehead & Spine */}
          <path
            d="M 98 98 C 118 79, 154 74, 184 85 C 197 90, 206 99, 211 108"
            fill="none"
            stroke={`url(#${uid}-rim)`}
            strokeWidth="3.2"
            strokeLinecap="round"
          />
          <ellipse
            cx="166"
            cy="88"
            rx="18"
            ry="5"
            transform="rotate(8 166 88)"
            fill="#e0f2fe"
            opacity="0.14"
          />

          {/* Subtle Cyber-Tech Collar Band with Signature 2x2 Commit Guardian Badge */}
          <g opacity="0.92">
            <path
              d="M 136 80 C 132 105, 134 138, 146 164"
              fill="none"
              stroke={pal.accent}
              strokeWidth="1.2"
              strokeDasharray="4 4"
              opacity="0.45"
            />
            <g transform="translate(132, 133) rotate(-8)">
              <rect x="0" y="0" width="5" height="5" rx="1" fill="#e94a32" />
              <rect x="6.5" y="0" width="5" height="5" rx="1" fill="#f8fafc" />
              <rect x="0" y="6.5" width="5" height="5" rx="1" fill="#f8fafc" />
              <rect x="6.5" y="6.5" width="5" height="5" rx="1" fill="#94a3b8" opacity="0.65" />
            </g>
          </g>
        </g>

        {/* 5. EXPRESSIVE FACE RIG (Eye-Patch, Cursor-Tracking Eyes, Brows, Talking Mouth) */}
        <g style={{ transform: `translate(${headShiftX}px, ${headShiftY}px)`, transition: 'transform 120ms ease-out' }}>
          {/* Iconic White Post-Ocular Orca Eye Patch */}
          <path
            d="M 130 109
               C 134 99, 151 96, 163 102
               C 168 105, 166 113, 156 116
               C 143 119, 128 116, 130 109 Z"
            fill="#f8fafc"
          />

          {/* Far-Side Eye Hint (gives 3/4 face depth) */}
          <g transform="translate(205, 117)">
            {happy ? (
              <path
                d="M -4 1 Q 0 -4 4 1"
                fill="none"
                stroke={pal.accent}
                strokeWidth="2.1"
                strokeLinecap="round"
              />
            ) : (
              <>
                <ellipse cx="0" cy="0" rx="4.2" ry={isBlinking ? 0.8 : 5.4} fill="#060911" stroke="#334155" strokeWidth="0.8" />
                {!isBlinking && (
                  <>
                    <ellipse
                      cx={px * 0.4}
                      cy={py * 0.4}
                      rx="2.3"
                      ry="3.1"
                      fill={`url(#${uid}-iris)`}
                    />
                    <circle cx={-1 + px * 0.3} cy={-1.6 + py * 0.3} r="1.1" fill="#ffffff" />
                  </>
                )}
              </>
            )}
          </g>

          {/* Near Expressive Anime-Marine Eye (cx=178, cy=120) */}
          <g transform="translate(178, 120)">
            {happy ? (
              /* Joyful upturned ^ crescent eye */
              <>
                <path
                  d="M -9 2 Q 0 -9 9 2"
                  fill="none"
                  stroke="#f8fafc"
                  strokeWidth="3.2"
                  strokeLinecap="round"
                />
                <path
                  d="M -9 2 Q 0 -9 9 2"
                  fill="none"
                  stroke={pal.accent}
                  strokeWidth="1.4"
                  strokeLinecap="round"
                  opacity="0.85"
                />
              </>
            ) : (
              <>
                {/* Eye socket + outer sclera */}
                <ellipse
                  cx="0"
                  cy="0"
                  rx="10.2"
                  ry={isBlinking ? 1.1 : 10.8}
                  fill="#04070e"
                  stroke={angry ? pal.accent : '#334155'}
                  strokeWidth={angry ? 1.4 : 1.1}
                />
                {!isBlinking && (
                  <g style={{ transform: `translate(${px}px, ${py}px)`, transition: 'transform 80ms linear' }}>
                    {/* Glowing Iris */}
                    <circle cx="0" cy="0.5" r="7.2" fill={`url(#${uid}-iris)`} />
                    {/* Deep Pupil */}
                    <circle cx="0.6" cy="0.8" r={angry ? 3.2 : 4.1} fill="#030712" />
                    {/* Dual Glossy Specular Catchlights */}
                    <circle cx="-2.6" cy="-2.8" r="2.3" fill="#ffffff" />
                    <circle cx="2.6" cy="2.9" r="1.1" fill="#ffffff" opacity="0.85" />
                  </g>
                )}
                {/* Eyelid blink line */}
                {isBlinking && (
                  <path
                    d="M -10 0 Q 0 3 10 0"
                    fill="none"
                    stroke="#94a3b8"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                  />
                )}
              </>
            )}

            {/* Mood Eyebrow */}
            {angry && (
              <path
                d="M -11 -12 L 10 -6"
                fill="none"
                stroke="#ff735d"
                strokeWidth="3"
                strokeLinecap="round"
              />
            )}
            {scanning && !angry && (
              <path
                d="M -10 -12 Q 0 -13 10 -10"
                fill="none"
                stroke={pal.accent}
                strokeWidth="2.2"
                strokeLinecap="round"
              />
            )}
          </g>

          {/* Soft Cute Cheek Blush on Happy or Idle Talking */}
          {(happy || (mood === 'idle' && isTalking)) && (
            <ellipse
              cx="166"
              cy="135"
              rx="7.5"
              ry="3.6"
              fill="#fb7185"
              opacity={happy ? 0.42 : 0.24}
            />
          )}

          {/* === REAL ARTICULATED TALKING MOUTH RIG === */}
          <g id="orca-mouth-rig">
            {activeMouth === 0 && (
              /* Closed expression mouth */
              angry ? (
                <path
                  d="M 183 147 Q 196 142 209 146"
                  fill="none"
                  stroke="#0f172a"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                />
              ) : happy ? (
                <path
                  d="M 181 141 Q 195 152 211 142"
                  fill="none"
                  stroke="#0f172a"
                  strokeWidth="2.6"
                  strokeLinecap="round"
                />
              ) : (
                <path
                  d="M 183 144 Q 196 149 210 142"
                  fill="none"
                  stroke="#0f172a"
                  strokeWidth="2.4"
                  strokeLinecap="round"
                />
              )
            )}

            {activeMouth === 1 && (
              /* Viseme 1: Parted speech mouth (soft syllable) */
              <g>
                <path
                  d="M 183 143 Q 196 146 209 142 Q 204 152 194 152 Q 186 151 183 143 Z"
                  fill="#220d1b"
                  stroke="#0f172a"
                  strokeWidth="1.6"
                />
                <ellipse cx="195" cy="150" rx="5.5" ry="2" fill="#fb7185" opacity="0.88" />
                <path d="M 188 144 Q 196 146 204 144" stroke="#ffffff" strokeWidth="1.4" fill="none" strokeLinecap="round" />
              </g>
            )}

            {activeMouth === 2 && (
              /* Viseme 2: Open talking mouth (vowels a/e/i) */
              <g>
                <path
                  d="M 181 142 Q 196 145 211 141 Q 208 158 194 158 Q 183 157 181 142 Z"
                  fill="#240c1b"
                  stroke="#0f172a"
                  strokeWidth="1.7"
                />
                <path
                  d="M 187 154 Q 195 149 203 154 Q 198 158 192 158 Z"
                  fill="#fb7185"
                />
                <path d="M 186 143 Q 196 145 206 143" stroke="#ffffff" strokeWidth="2.1" fill="none" strokeLinecap="round" />
              </g>
            )}

            {activeMouth === 3 && (
              /* Viseme 3: Wide expressive emphasis mouth (o/u/exclamation) */
              <g>
                <path
                  d="M 181 141 Q 196 143 212 140 Q 210 162 195 162 Q 182 161 181 141 Z"
                  fill="#260b1c"
                  stroke="#0f172a"
                  strokeWidth="1.8"
                />
                <ellipse cx="195" cy="157" rx="8" ry="4" fill="#fb7185" />
                <path d="M 185 142 Q 196 144 207 142" stroke="#ffffff" strokeWidth="2.3" fill="none" strokeLinecap="round" />
              </g>
            )}
          </g>

          {/* Animated Sound Waves emanating from mouth while speaking */}
          {isTalking && !paused && (
            <g stroke={pal.accent} fill="none" strokeLinecap="round">
              <path
                d="M 222 135 Q 228 144 222 153"
                strokeWidth="2.2"
                className="orca-sound-arc"
              />
              <path
                d="M 229 130 Q 238 144 229 158"
                strokeWidth="1.8"
                opacity="0.7"
                className="orca-sound-arc-delayed"
              />
            </g>
          )}

          {/* Holographic Cyber-Visor when Scanning or Thinking */}
          {scanning && (
            <g filter={`url(#${uid}-glow)`}>
              <path
                d="M 161 108 L 214 106 L 217 124 L 163 128 Z"
                fill={`url(#${uid}-visor)`}
                stroke={pal.accent}
                strokeWidth="1.6"
                strokeLinejoin="round"
              />
              <line x1="164" y1="118" x2="215" y2="115" stroke="#ffffff" strokeWidth="1" opacity="0.65" />
            </g>
          )}
        </g>

        {/* 6. NEAR PECTORAL FIN (in front of belly, waves when talking! pivot 146, 156) */}
        <g className={cn(!paused && (isTalking || happy ? 'orca-fin-front-wave' : 'orca-fin-front-bone'))}>
          <path
            d="M 146 154
               C 132 168, 117 190, 126 203
               C 137 211, 156 196, 166 172
               C 167 164, 158 156, 146 154 Z"
            fill={`url(#${uid}-skin-fin)`}
            stroke="#24334b"
            strokeWidth="1.25"
          />
          {/* Subtle fin gloss arc */}
          <path
            d="M 145 162 C 137 174, 132 186, 134 196"
            fill="none"
            stroke={pal.accent}
            strokeWidth="1.3"
            strokeLinecap="round"
            opacity="0.45"
          />
        </g>
      </g>

      {/* === MOOD-SPECIFIC FLOATING HUD BADGES === */}
      {/* Blocked / Alert Hexagonal Crimson Barrier Shield (outer translates, inner animates) */}
      {angry && (
        <g transform="translate(216, 62)">
          <g className={cn(!paused && 'orca-shield-float')}>
            <polygon
              points="0,-23 20,-11.5 20,11.5 0,23 -20,11.5 -20,-11.5"
              fill="rgba(233, 74, 50, 0.24)"
              stroke="#ff5a3c"
              strokeWidth="2.2"
              filter={`url(#${uid}-glow)`}
            />
            <line x1="0" y1="-9.5" x2="0" y2="2.5" stroke="#ffffff" strokeWidth="3.2" strokeLinecap="round" />
            <circle cx="0" cy="9.5" r="2.1" fill="#ffffff" />
          </g>
        </g>
      )}

      {/* Happy Emerald Verified Check Badge (outer translates, inner animates) */}
      {happy && (
        <g transform="translate(216, 62)">
          <g className={cn(!paused && 'orca-shield-float')}>
            <circle
              cx="0"
              cy="0"
              r="19"
              fill="rgba(63, 191, 127, 0.22)"
              stroke="#3fbf7f"
              strokeWidth="2"
              filter={`url(#${uid}-glow)`}
            />
            <path
              d="M -7.5 1 L -2 6.5 L 8.5 -5.5"
              fill="none"
              stroke="#ffffff"
              strokeWidth="3.1"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </g>
        </g>
      )}

      {/* Scanning Echolocation Forward Sonar Pulses */}
      {scanning && !paused && (
        <g transform="translate(218, 96)" stroke={pal.accent} fill="none" strokeLinecap="round">
          <path d="M 4 -12 Q 16 0 4 12" strokeWidth="2.2" className="orca-sound-arc" />
          <path d="M 12 -18 Q 28 0 12 18" strokeWidth="1.6" opacity="0.7" className="orca-sound-arc-delayed" />
        </g>
      )}
    </svg>
  );
}

/** Crisp lightweight 16x16 pixel-art Orca sprite badge for chat headers & message bubbles. */
export function OrcaMiniAvatar({
  mood = 'idle',
  className,
}: {
  mood?: OrcaMood;
  className?: string;
}) {
  const pal = MOOD_PALETTE[mood];
  const angry = mood === 'alert' || mood === 'blocked';
  const happy = mood === 'happy';
  const scanning = mood === 'scanning' || mood === 'thinking';

  return (
    <span
      aria-hidden="true"
      className={cn(
        'inline-flex items-center justify-center w-7 h-7 border-2 border-[var(--color-line-strong)] bg-[#0b0e18] shadow-[2px_2px_0_var(--pixel-shadow)] shrink-0 overflow-hidden',
        className
      )}
    >
      <svg viewBox="0 0 16 16" shapeRendering="crispEdges" className="pixel-art w-full h-full">
        {/* Midnight aurora sky backdrop */}
        <rect x="0" y="0" width="16" height="16" fill="#0b0e18" />
        <rect x="0" y="2" width="10" height="2" fill="#1f6e6c" />
        <rect x="6" y="3" width="10" height="2" fill="#4c3e8f" />
        <rect x="13" y="1" width="2" height="2" fill="#ffe79e" />
        {/* Pixel dorsal fin + mood LED */}
        <rect x="4" y="3" width="2" height="2" fill="#151f38" />
        <rect x="5" y="4" width="3" height="2" fill="#151f38" />
        <rect x="4" y="3" width="1" height="2" fill={pal.accent} />
        {/* Pixel Orca head & obsidian body */}
        <rect x="2" y="6" width="12" height="7" fill="#151f38" />
        <rect x="3" y="5" width="10" height="2" fill="#23345c" />
        <rect x="13" y="8" width="2" height="4" fill="#151f38" />
        {/* White belly jaw */}
        <rect x="4" y="12" width="10" height="2" fill="#eef6ff" />
        <rect x="11" y="11" width="3" height="2" fill="#eef6ff" />
        {/* White post-ocular patch */}
        <rect x="4" y="7" width="3" height="2" fill="#eef6ff" />
        {/* Cozy red winter scarf accent */}
        <rect x="2" y="10" width="2" height="3" fill="#e94a32" />
        {/* Expressive pixel eye */}
        {happy ? (
          <>
            <rect x="9" y="9" width="1" height="1" fill="#47d18c" />
            <rect x="10" y="8" width="2" height="1" fill="#47d18c" />
            <rect x="12" y="9" width="1" height="1" fill="#47d18c" />
          </>
        ) : (
          <>
            <rect x="9" y="8" width="3" height="3" fill="#05070e" />
            <rect x="10" y="9" width="2" height="2" fill={pal.irisTop} />
            <rect x="10" y="9" width="1" height="1" fill="#ffffff" />
            {angry && <rect x="9" y="7" width="3" height="1" fill="#ff6b57" />}
          </>
        )}
        {/* Pixel cyber-visor when scanning */}
        {scanning && (
          <rect x="8" y="8" width="5" height="3" fill={pal.accent} fillOpacity="0.45" />
        )}
      </svg>
    </span>
  );
}
