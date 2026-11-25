'use client';

import { cn } from '@/lib/utils';

/** Crisp 16x16 pixel Christmas Tree icon with golden star & ornaments for the navbar brand. */
export function ChristmasTreeBadge({ className }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'inline-flex items-center justify-center w-6 h-6 border-2 border-[#ffd866] bg-[#081119] shadow-[2px_2px_0_var(--pixel-shadow)] shrink-0',
        className
      )}
    >
      <svg viewBox="0 0 16 16" shapeRendering="crispEdges" className="pixel-art w-full h-full">
        <rect x="0" y="0" width="16" height="16" fill="#081119" />
        {/* Golden pixel star topper */}
        <rect x="7" y="1" width="2" height="2" fill="#ffd866" />
        <rect x="6" y="2" width="4" height="1" fill="#fff2b2" />
        {/* Layered snowy pine tree */}
        <rect x="6" y="3" width="4" height="2" fill="#2d8a5b" />
        <rect x="5" y="5" width="6" height="2" fill="#23734a" />
        <rect x="4" y="7" width="8" height="2" fill="#2d8a5b" />
        <rect x="3" y="9" width="10" height="3" fill="#1d5e3c" />
        {/* Snow highlights */}
        <rect x="6" y="4" width="2" height="1" fill="#eef7ff" />
        <rect x="9" y="6" width="2" height="1" fill="#eef7ff" />
        <rect x="4" y="10" width="2" height="1" fill="#eef7ff" />
        {/* Colorful ornaments */}
        <rect x="8" y="5" width="1" height="1" fill="#ff5247" />
        <rect x="5" y="8" width="1" height="1" fill="#ffd866" />
        <rect x="10" y="9" width="1" height="1" fill="#ff5247" />
        <rect x="7" y="10" width="1" height="1" fill="#6ce4ff" />
        {/* Trunk & tiny gift */}
        <rect x="7" y="12" width="2" height="3" fill="#6e442f" />
        <rect x="10" y="12" width="3" height="3" fill="#e93e32" />
        <rect x="11" y="12" width="1" height="3" fill="#ffd866" />
      </svg>
    </span>
  );
}

/**
 * Full-width 16-bit Pixel Christmas Pine Garland & Twinkling Fairy Lights strung under the top bar.
 * Pure crisp SVG + slow (<0.6Hz) compositor opacity twinkle; pauses cleanly via .orca-paused / prefers-reduced-motion.
 */
export function ChristmasLightsGarland({ paused = false }: { paused?: boolean }) {
  const bulbs = [
    { x: 10, y: 10, color: '#ff5247', glow: '#ff9b93', group: 'a' },
    { x: 34, y: 12, color: '#ffd866', glow: '#fff2b2', group: 'b' },
    { x: 58, y: 10, color: '#47d18c', glow: '#9ef5c6', group: 'a' },
    { x: 82, y: 12, color: '#6ce4ff', glow: '#c2f4ff', group: 'b' },
    { x: 106, y: 10, color: '#ff5247', glow: '#ff9b93', group: 'a' },
    { x: 130, y: 12, color: '#ffd866', glow: '#fff2b2', group: 'b' },
    { x: 154, y: 10, color: '#47d18c', glow: '#9ef5c6', group: 'a' },
    { x: 178, y: 12, color: '#6ce4ff', glow: '#c2f4ff', group: 'b' },
  ] as const;

  return (
    <div
      aria-hidden="true"
      className={cn(
        'pointer-events-none relative w-full h-[18px] overflow-hidden shrink-0 select-none bg-transparent -mb-[14px] z-20',
        paused && 'orca-paused'
      )}
    >
      <div className="flex w-full h-full">
        {Array.from({ length: 10 }).map((_, seg) => (
          <svg
            key={seg}
            viewBox="0 0 192 18"
            shapeRendering="crispEdges"
            className="pixel-art h-[18px] w-[192px] shrink-0"
          >
            {/* Dark pine bough swag across the top border */}
            <rect x="0" y="0" width="192" height="2" fill="#1b4d3a" />
            <rect x="4" y="2" width="18" height="2" fill="#256b4f" />
            <rect x="28" y="2" width="18" height="3" fill="#1d5940" />
            <rect x="52" y="2" width="18" height="2" fill="#256b4f" />
            <rect x="76" y="2" width="18" height="3" fill="#1d5940" />
            <rect x="100" y="2" width="18" height="2" fill="#256b4f" />
            <rect x="124" y="2" width="18" height="3" fill="#1d5940" />
            <rect x="148" y="2" width="18" height="2" fill="#256b4f" />
            <rect x="172" y="2" width="18" height="3" fill="#1d5940" />

            {/* Crisp snow & red holly berries tucked in the pine garland */}
            <rect x="18" y="2" width="6" height="2" fill="#eef7ff" />
            <rect x="66" y="2" width="6" height="2" fill="#eef7ff" />
            <rect x="114" y="2" width="6" height="2" fill="#eef7ff" />
            <rect x="162" y="2" width="6" height="2" fill="#eef7ff" />
            <rect x="44" y="2" width="2" height="2" fill="#e93e32" />
            <rect x="47" y="3" width="2" height="2" fill="#e93e32" />
            <rect x="140" y="2" width="2" height="2" fill="#e93e32" />
            <rect x="143" y="3" width="2" height="2" fill="#e93e32" />

            {/* Scalloped wire connecting hanging pixel bulbs */}
            <rect x="0" y="5" width="192" height="1" fill="#0d261d" />
            <rect x="20" y="6" width="28" height="1" fill="#0d261d" />
            <rect x="68" y="6" width="28" height="1" fill="#0d261d" />
            <rect x="116" y="6" width="28" height="1" fill="#0d261d" />
            <rect x="164" y="6" width="28" height="1" fill="#0d261d" />

            {/* Hanging 16-bit glowing Christmas fairy-light bulbs */}
            {bulbs.map((b, idx) => (
              <g key={idx}>
                <rect x={b.x} y={b.y - 4} width="2" height="3" fill="#26473a" />
                <g className={b.group === 'a' ? 'xmas-bulb-a' : 'xmas-bulb-b'}>
                  <rect x={b.x - 1} y={b.y - 1} width="4" height="5" fill={b.color} />
                  <rect x={b.x} y={b.y} width="2" height="2" fill={b.glow} />
                  <rect x={b.x} y={b.y + 4} width="2" height="1" fill={b.color} />
                </g>
              </g>
            ))}
          </svg>
        ))}
      </div>
    </div>
  );
}

const SNOW_PARTICLES: ReadonlyArray<{
  left: string;
  size: number;
  duration: string;
  delay: string;
  color: string;
}> = [
  { left: '4%', size: 3, duration: '11s', delay: '-2s', color: '#eef7ff' },
  { left: '11%', size: 2, duration: '14s', delay: '-7s', color: '#b8dcf7' },
  { left: '18%', size: 4, duration: '12s', delay: '-4s', color: '#ffffff' },
  { left: '25%', size: 2, duration: '15s', delay: '-10s', color: '#cde8ff' },
  { left: '33%', size: 3, duration: '10.5s', delay: '-1s', color: '#eef7ff' },
  { left: '41%', size: 2, duration: '13.5s', delay: '-8s', color: '#ffd866' },
  { left: '49%', size: 3, duration: '12.5s', delay: '-5s', color: '#ffffff' },
  { left: '57%', size: 2, duration: '16s', delay: '-11s', color: '#b8dcf7' },
  { left: '64%', size: 4, duration: '11.5s', delay: '-3s', color: '#eef7ff' },
  { left: '72%', size: 2, duration: '14.5s', delay: '-9s', color: '#cde8ff' },
  { left: '79%', size: 3, duration: '12s', delay: '-6s', color: '#ffffff' },
  { left: '86%', size: 2, duration: '13s', delay: '-2.5s', color: '#b8dcf7' },
  { left: '93%', size: 3, duration: '10s', delay: '-7.5s', color: '#eef7ff' },
  { left: '97%', size: 2, duration: '15s', delay: '-4.5s', color: '#ffd866' },
];

/**
 * Featherweight pure-CSS 16-bit falling pixel snow overlay for the chat sky.
 * Zero JS loop, compositor-only transforms, stops cleanly when paused or prefers-reduced-motion is set.
 */
export function PixelSnowfallLayer({ paused = false }: { paused?: boolean }) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        'pointer-events-none absolute inset-0 overflow-hidden z-0 select-none',
        paused && 'orca-paused'
      )}
    >
      {SNOW_PARTICLES.map((p, idx) => (
        <span
          key={idx}
          className="xmas-snow-flake absolute top-[-8px] block opacity-55"
          style={{
            left: p.left,
            width: `${p.size}px`,
            height: `${p.size}px`,
            backgroundColor: p.color,
            animationDuration: p.duration,
            animationDelay: p.delay,
          }}
        />
      ))}
    </div>
  );
}

/** Subtle 16-bit snowy pine & gift-box horizon resting along the bottom of the chat stream. */
export function PixelWinterHorizon() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none sticky bottom-0 left-0 right-0 h-[22px] -mx-4 sm:-mx-6 -mb-4 mt-auto overflow-hidden select-none opacity-80 z-0"
    >
      <div className="flex w-full h-full items-end">
        {Array.from({ length: 8 }).map((_, seg) => (
          <svg
            key={seg}
            viewBox="0 0 200 22"
            shapeRendering="crispEdges"
            className="pixel-art h-[22px] w-[200px] shrink-0"
          >
            {/* Distant snowy pine silhouettes */}
            <rect x="14" y="6" width="2" height="12" fill="#184235" />
            <rect x="12" y="9" width="6" height="9" fill="#184235" />
            <rect x="10" y="13" width="10" height="5" fill="#215947" />
            <rect x="13" y="8" width="4" height="1" fill="#cce6ff" />

            <rect x="74" y="4" width="2" height="14" fill="#14382c" />
            <rect x="71" y="7" width="8" height="11" fill="#1d4f3f" />
            <rect x="68" y="12" width="14" height="6" fill="#24634e" />
            <rect x="74" y="3" width="2" height="2" fill="#ffd866" />
            <rect x="72" y="10" width="2" height="2" fill="#e93e32" />
            <rect x="77" y="13" width="2" height="2" fill="#ffd866" />

            <rect x="148" y="8" width="2" height="10" fill="#184235" />
            <rect x="145" y="11" width="8" height="7" fill="#215947" />
            <rect x="147" y="10" width="4" height="1" fill="#eef7ff" />

            {/* Tiny pixel gift boxes sitting in the snow */}
            <rect x="84" y="14" width="5" height="4" fill="#e93e32" />
            <rect x="86" y="14" width="1" height="4" fill="#ffd866" />
            <rect x="160" y="15" width="4" height="3" fill="#2d8a5b" />
            <rect x="161" y="15" width="2" height="1" fill="#ff5247" />

            {/* Crisp snowdrift ground bank */}
            <rect x="0" y="18" width="200" height="2" fill="#cbe5ff" />
            <rect x="0" y="20" width="200" height="2" fill="#8fb8e3" />
            <rect x="24" y="17" width="28" height="2" fill="#eef7ff" />
            <rect x="108" y="17" width="34" height="2" fill="#eef7ff" />
            <rect x="174" y="17" width="22" height="2" fill="#eef7ff" />
          </svg>
        ))}
      </div>
    </div>
  );
}
