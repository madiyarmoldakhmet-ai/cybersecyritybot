'use client';

import { useEffect, useRef } from 'react';
import type { OrcaMood } from '@/components/OrcaRigSvg';

interface PixelOrcaSceneProps {
  mood: OrcaMood;
  isTalking: boolean;
  /** 0 = closed, 1 = slight open, 2 = medium open, 3 = wide open */
  mouthLevel: number;
  paused?: boolean;
  /** Normalized cursor offset in [-1, 1] */
  lookX?: number;
  lookY?: number;
  /** Incremented whenever the user clicks/pokes the orca */
  pokeTrigger?: number;
  className?: string;
}

const W = 160;
const H = 120;

const STARS: ReadonlyArray<[number, number, number, string]> = [
  [7, 5, 0.35, '#eaf4ff'],
  [18, 11, 0.52, '#7d95c2'],
  [29, 4, 0.28, '#ffe79e'],
  [41, 14, 0.44, '#eaf4ff'],
  [52, 7, 0.61, '#8fa6d4'],
  [65, 5, 0.33, '#eaf4ff'],
  [77, 13, 0.49, '#ffe79e'],
  [88, 6, 0.41, '#7d95c2'],
  [99, 10, 0.56, '#eaf4ff'],
  [112, 5, 0.37, '#8fa6d4'],
  [119, 15, 0.46, '#eaf4ff'],
  [149, 7, 0.31, '#ffe79e'],
  [154, 15, 0.54, '#8fa6d4'],
  [12, 22, 0.42, '#7d95c2'],
  [35, 25, 0.51, '#eaf4ff'],
  [58, 19, 0.38, '#7d95c2'],
  [84, 21, 0.47, '#eaf4ff'],
  [105, 24, 0.34, '#ffe79e'],
  [144, 24, 0.48, '#eaf4ff'],
  [153, 33, 0.39, '#7d95c2'],
  [6, 36, 0.45, '#8fa6d4'],
  [73, 34, 0.53, '#eaf4ff'],
  [116, 35, 0.36, '#8fa6d4'],
];

const SNOWFLAKES: ReadonlyArray<{ x: number; y: number; speed: number; phase: number; size: number }> = [
  { x: 10, y: 12, speed: 6, phase: 0.2, size: 1 },
  { x: 24, y: 40, speed: 8, phase: 1.1, size: 1 },
  { x: 38, y: 8, speed: 7, phase: 2.3, size: 2 },
  { x: 52, y: 55, speed: 6, phase: 0.8, size: 1 },
  { x: 66, y: 26, speed: 9, phase: 3.0, size: 1 },
  { x: 78, y: 64, speed: 7, phase: 1.9, size: 1 },
  { x: 92, y: 18, speed: 8, phase: 4.1, size: 2 },
  { x: 106, y: 44, speed: 6, phase: 2.7, size: 1 },
  { x: 118, y: 10, speed: 8, phase: 0.5, size: 1 },
  { x: 132, y: 52, speed: 7, phase: 3.6, size: 1 },
  { x: 146, y: 22, speed: 9, phase: 1.4, size: 2 },
  { x: 155, y: 68, speed: 6, phase: 2.2, size: 1 },
  { x: 19, y: 78, speed: 7, phase: 3.9, size: 1 },
  { x: 138, y: 84, speed: 8, phase: 0.9, size: 1 },
];

const MOON_BITMAP = [
  '....###..',
  '..#####..',
  '.#####...',
  '#####....',
  '####.....',
  '####.....',
  '####.....',
  '#####....',
  '.#####...',
  '..######.',
  '....####.',
];

const MOOD_COLORS: Record<
  OrcaMood,
  {
    auroraA: [string, string, string];
    auroraB: [string, string, string];
    led: string;
    iris: string;
  }
> = {
  idle: {
    auroraA: ['#164949', '#248278', '#56d4b2'],
    auroraB: ['#2d2759', '#4c3e8f', '#8e7ef0'],
    led: '#56d4b2',
    iris: '#56d4b2',
  },
  thinking: {
    auroraA: ['#543d18', '#a67628', '#ffe79e'],
    auroraB: ['#2d2759', '#5644a3', '#9a8cf5'],
    led: '#ffe79e',
    iris: '#ffe79e',
  },
  scanning: {
    auroraA: ['#124659', '#248db0', '#6ce4ff'],
    auroraB: ['#164f4d', '#2ca890', '#6ef0cc'],
    led: '#6ce4ff',
    iris: '#6ce4ff',
  },
  alert: {
    auroraA: ['#5c191a', '#b33224', '#ff6b57'],
    auroraB: ['#382254', '#6b2c5c', '#c94c4c'],
    led: '#ff6b57',
    iris: '#ff6b57',
  },
  blocked: {
    auroraA: ['#5c191a', '#b33224', '#e94a32'],
    auroraB: ['#33204d', '#632952', '#b83c3c'],
    led: '#e94a32',
    iris: '#ff6b57',
  },
  happy: {
    auroraA: ['#17523d', '#2f996d', '#5ee8a7'],
    auroraB: ['#1b4d5c', '#2da890', '#8ef5d4'],
    led: '#5ee8a7',
    iris: '#5ee8a7',
  },
};

function px(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, color: string) {
  ctx.fillStyle = color;
  ctx.fillRect(Math.round(x), Math.round(y), Math.round(w), Math.round(h));
}

function drawPine(ctx: CanvasRenderingContext2D, cx: number, baseY: number, tiers: number) {
  // Trunk
  px(ctx, cx - 1, baseY - 3, 3, 4, '#3a271f');
  for (let i = 0; i < tiers; i += 1) {
    const ty = baseY - 4 - i * 4;
    const half = Math.max(1, (tiers - i) * 2 + 1);
    px(ctx, cx - half, ty, half * 2 + 1, 3, '#174238');
    px(ctx, cx - half + 1, ty - 1, half * 2 - 1, 2, '#246656');
    px(ctx, cx - Math.max(1, half - 2), ty - 2, Math.max(2, (half - 2) * 2 + 1), 1, '#318770');
    // Snow cap pixels on pine boughs
    if (i % 2 === 1 || i === tiers - 1) {
      px(ctx, cx - Math.max(0, half - 1), ty - 1, Math.min(3, half), 1, '#dceeff');
      px(ctx, cx + Math.max(0, half - 2), ty, 2, 1, '#b8d7f5');
    }
  }
  // Snowy tree tip
  px(ctx, cx, baseY - 4 - tiers * 4, 1, 2, '#eef6ff');
}

function drawCabin(ctx: CanvasRenderingContext2D, x: number, y: number, t: number) {
  // Subtle chimney smoke puffs rising gently
  const smokeStep = Math.floor(t * 2) % 6;
  px(ctx, x + 23 + (smokeStep % 2), y - 6 - smokeStep, 2, 2, 'rgba(184, 212, 245, 0.5)');
  px(ctx, x + 24, y - 10 - ((smokeStep + 3) % 6), 2, 2, 'rgba(160, 190, 230, 0.3)');

  // Chimney
  px(ctx, x + 22, y - 2, 4, 8, '#463f66');
  px(ctx, x + 21, y - 3, 6, 1, '#eef6ff');

  // Pitched roof (deep twilight violet + snow top)
  for (let row = 0; row < 10; row += 1) {
    const rx = x + 14 - row - 2;
    const rw = 6 + row * 2;
    px(ctx, rx, y + row, rw, 1, row % 2 === 0 ? '#362d52' : '#2a2342');
    // Snow edges along roof slope
    px(ctx, rx - 1, y + row, 2, 1, '#eef6ff');
    px(ctx, rx + rw - 1, y + row, 2, 1, '#eef6ff');
  }
  // Roof peak snow
  px(ctx, x + 13, y - 1, 4, 1, '#ffffff');
  // Green pine trim & hanging pixel icicles under eaves
  px(ctx, x + 2, y + 10, 26, 1, '#266e5b');
  for (let ic = 3; ic <= 26; ic += 4) {
    px(ctx, x + ic, y + 11, 1, (ic % 8 === 3) ? 3 : 2, '#b8dcf7');
  }

  // Wooden log cabin body
  px(ctx, x + 3, y + 11, 24, 13, '#57372a');
  for (let logY = 13; logY <= 22; logY += 3) {
    px(ctx, x + 3, y + logY, 24, 1, '#40261c');
  }

  // Warm glowing pixel windows (echoing the cozy cottage in reference photo)
  const glow = Math.sin(t * 1.4) > -0.3 ? '#ffe79e' : '#f0b541';
  px(ctx, x + 5, y + 14, 5, 5, '#2b1b16');
  px(ctx, x + 6, y + 15, 3, 3, glow);
  px(ctx, x + 7, y + 15, 1, 3, '#8f5f24');

  px(ctx, x + 20, y + 14, 5, 5, '#2b1b16');
  px(ctx, x + 21, y + 15, 3, 3, glow);
  px(ctx, x + 22, y + 15, 1, 3, '#8f5f24');

  // Door with tiny green wreath & crimson berry
  px(ctx, x + 12, y + 15, 6, 9, '#2b1b16');
  px(ctx, x + 13, y + 16, 4, 8, '#3d251d');
  px(ctx, x + 14, y + 17, 2, 2, '#2f8f6b');
  px(ctx, x + 15, y + 18, 1, 1, '#e94a32');
  px(ctx, x + 16, y + 20, 1, 1, '#ffe79e'); // Brass knob
}

function drawMiniSnowman(ctx: CanvasRenderingContext2D, x: number, y: number) {
  // Subtle nostalgic snowman silhouette on far snowy shore
  px(ctx, x + 1, y - 9, 4, 2, '#1b2640'); // top hat
  px(ctx, x, y - 7, 6, 1, '#e94a32'); // red hat band
  px(ctx, x + 1, y - 6, 4, 3, '#eef6ff'); // head
  px(ctx, x + 2, y - 5, 1, 1, '#0b0e18'); // eye
  px(ctx, x + 4, y - 5, 2, 1, '#f08b33'); // carrot nose
  px(ctx, x + 1, y - 3, 5, 1, '#e94a32'); // red scarf
  px(ctx, x + 4, y - 2, 1, 2, '#e94a32'); // scarf tail
  px(ctx, x, y - 2, 6, 4, '#eef6ff'); // body
  px(ctx, x + 2, y - 1, 1, 1, '#243554'); // button
}

function drawOrca(
  ctx: CanvasRenderingContext2D,
  ox: number,
  oy: number,
  t: number,
  mood: OrcaMood,
  isTalking: boolean,
  mouthLevel: number,
  lookX: number,
  lookY: number,
  isBlinking: boolean,
  paused: boolean
) {
  const pal = MOOD_COLORS[mood];
  const fast = mood === 'scanning' || mood === 'happy' || isTalking;
  const tailShift = paused ? 0 : Math.round(Math.sin(t * (fast ? 5.2 : 2.6)) * 2);
  const finShift = paused ? 0 : Math.round(Math.sin(t * (isTalking || mood === 'happy' ? 6.4 : 2.4)));
  const scarfWave = paused ? 0 : Math.round(Math.sin(t * 4.2));
  const angry = mood === 'alert' || mood === 'blocked';
  const happy = mood === 'happy';
  const scanning = mood === 'scanning' || mood === 'thinking';

  // 1. Tail peduncle & pixel flukes (left side)
  px(ctx, ox - 20, oy + 1 + tailShift, 8, 5, '#070a14');
  px(ctx, ox - 19, oy + 2 + tailShift, 7, 3, '#17223b');
  // Upper fluke
  px(ctx, ox - 26, oy - 5 + tailShift, 5, 3, '#070a14');
  px(ctx, ox - 25, oy - 4 + tailShift, 4, 2, '#223357');
  px(ctx, ox - 23, oy - 2 + tailShift, 5, 4, '#17223b');
  // Lower fluke
  px(ctx, ox - 25, oy + 5 + tailShift, 6, 3, '#070a14');
  px(ctx, ox - 24, oy + 5 + tailShift, 4, 2, '#17223b');
  // Fluke edge LED glint
  px(ctx, ox - 25, oy - 4 + tailShift, 2, 1, pal.led);

  // 2. Tall Iconic Dorsal Fin + Cyber LED Strip
  px(ctx, ox - 6, oy - 14, 3, 2, '#070a14');
  px(ctx, ox - 5, oy - 12, 5, 3, '#070a14');
  px(ctx, ox - 4, oy - 9, 8, 4, '#070a14');
  px(ctx, ox - 4, oy - 12, 3, 2, '#1e2c4a');
  px(ctx, ox - 3, oy - 10, 5, 5, '#17223b');
  // Glowing mood LED along leading dorsal edge
  px(ctx, ox - 4, oy - 12, 1, 2, pal.led);
  px(ctx, ox - 3, oy - 10, 1, 2, pal.led);
  px(ctx, ox - 2, oy - 8, 1, 2, pal.led);

  // 3. Sleek Pixel Orca Body & Rounded Melon Head (dark outline first)
  px(ctx, ox - 12, oy - 5, 36, 16, '#070a14');
  px(ctx, ox - 9, oy - 7, 30, 3, '#070a14');
  px(ctx, ox + 22, oy - 3, 6, 12, '#070a14');
  px(ctx, ox + 26, oy + 1, 4, 8, '#070a14');
  px(ctx, ox - 10, oy + 10, 34, 3, '#070a14');

  // Main obsidian dorsal torso
  px(ctx, ox - 11, oy - 4, 34, 14, '#141d33');
  px(ctx, ox - 8, oy - 6, 28, 3, '#1a2642');
  px(ctx, ox + 21, oy - 2, 6, 10, '#141d33');
  px(ctx, ox + 25, oy + 2, 4, 6, '#141d33');

  // Crisp slate-blue top rim highlight along spine & melon forehead
  px(ctx, ox - 6, oy - 6, 22, 1, '#3d5685');
  px(ctx, ox + 15, oy - 5, 6, 1, '#5878b0');
  px(ctx, ox + 21, oy - 3, 3, 1, '#5878b0');

  // Classic smoky saddle patch behind dorsal fin
  px(ctx, ox - 8, oy - 3, 6, 3, '#3b4e73');
  px(ctx, ox - 7, oy - 4, 4, 1, '#4b6391');

  // Snow-white Orca Belly + Flank Flare
  px(ctx, ox - 9, oy + 7, 34, 4, '#eef6ff');
  px(ctx, ox - 7, oy + 10, 29, 2, '#bed9f7');
  px(ctx, ox + 22, oy + 6, 6, 3, '#eef6ff');
  px(ctx, ox - 10, oy + 5, 4, 3, '#eef6ff'); // iconic white flank sweep

  // Iconic White Post-Ocular Eye Patch
  px(ctx, ox + 4, oy - 2, 8, 3, '#eef6ff');
  px(ctx, ox + 5, oy - 3, 6, 1, '#ffffff');
  px(ctx, ox + 6, oy + 1, 5, 1, '#c9e4ff');

  // 4. Cozy Crimson Pixel Scarf (nod to the reference winter pixel scene!)
  px(ctx, ox + 1, oy - 3, 3, 13, '#b82e1d');
  px(ctx, ox + 2, oy - 2, 3, 11, '#e94a32');
  px(ctx, ox + 3, oy + 1, 1, 4, '#ff7b66'); // scarf knit highlight
  // Fluttering scarf tail trailing left
  px(ctx, ox - 3, oy + 4 + scarfWave, 4, 3, '#e94a32');
  px(ctx, ox - 6, oy + 5 + scarfWave, 3, 2, '#c83822');
  px(ctx, ox - 7, oy + 5 + scarfWave, 1, 2, '#ffe79e'); // gold fringe tip

  // 5. Expressive Pixel Eye (cursor tracking + blinking + mood)
  const ex = ox + 16;
  const ey = oy + 0;
  const dx = paused ? 0 : lookX > 0.25 ? 1 : lookX < -0.25 ? -1 : 0;
  const dy = paused ? 0 : lookY > 0.25 ? 1 : lookY < -0.25 ? -1 : 0;

  if (happy) {
    // Cheerful ^ pixel smile eye
    px(ctx, ex, ey + 1, 1, 1, '#eef6ff');
    px(ctx, ex + 1, ey, 3, 1, '#eef6ff');
    px(ctx, ex + 4, ey + 1, 1, 1, '#eef6ff');
    px(ctx, ex + 1, ey + 1, 3, 1, pal.led);
    // Cute pixel blush cheek
    px(ctx, ex - 2, ey + 4, 3, 1, '#ff7d99');
  } else if (isBlinking) {
    // Closed blink line
    px(ctx, ex, ey + 2, 5, 1, '#93add1');
  } else {
    // Crisp 5x5 pixel eye socket + glowing mood iris + pupil + white glint
    px(ctx, ex, ey, 5, 5, '#05070e');
    px(ctx, ex + 1, ey + 1, 3, 3, pal.iris);
    px(ctx, ex + 2 + dx, ey + 2 + dy, 1, 1, '#05070e');
    px(ctx, ex + 1, ey + 1, 1, 1, '#ffffff');
  }

  // Fierce pixel eyebrow on alert/blocked
  if (angry) {
    px(ctx, ex - 1, ey - 2, 3, 1, '#ff6b57');
    px(ctx, ex + 2, ey - 1, 3, 1, '#ff6b57');
  }

  // Glowing pixel cyber-visor on scanning/thinking
  if (scanning) {
    px(ctx, ex - 1, ey - 1, 9, 5, 'rgba(108, 228, 255, 0.28)');
    px(ctx, ex - 1, ey - 1, 9, 1, pal.led);
    px(ctx, ex - 1, ey + 3, 9, 1, pal.led);
    px(ctx, ex + 1, ey + 1, 5, 1, '#ffffff');
  }

  // 6. Articulated Talking Pixel Mouth (lip-sync levels 0..3)
  const mx = ox + 20;
  const my = oy + 6;
  const level = isTalking ? Math.max(0, Math.min(3, mouthLevel)) : 0;
  if (level === 0) {
    if (happy) {
      px(ctx, mx, my, 2, 1, '#0b0e18');
      px(ctx, mx + 2, my + 1, 4, 1, '#0b0e18');
      px(ctx, mx + 6, my, 2, 1, '#0b0e18');
    } else if (angry) {
      px(ctx, mx, my + 1, 2, 1, '#0b0e18');
      px(ctx, mx + 2, my, 4, 1, '#0b0e18');
      px(ctx, mx + 6, my + 1, 2, 1, '#0b0e18');
    } else {
      px(ctx, mx, my, 7, 1, '#0b0e18');
      px(ctx, mx + 7, my - 1, 1, 1, '#0b0e18');
    }
  } else {
    const mh = level === 1 ? 2 : level === 2 ? 4 : 5;
    px(ctx, mx, my - 1, 8, mh + 1, '#260b1c');
    px(ctx, mx + 1, my - 1, 6, 1, '#ffffff'); // upper teeth shine
    if (mh >= 2) {
      px(ctx, mx + 2, my + mh - 2, 4, 1, '#ff738f'); // pixel tongue
    }
  }

  // 7. Front Pectoral Fin (waves cheerfully when talking or happy!)
  px(ctx, ox + 6, oy + 9 + finShift, 6, 6, '#070a14');
  px(ctx, ox + 7, oy + 9 + finShift, 4, 5, '#192745');
  px(ctx, ox + 8, oy + 10 + finShift, 1, 3, pal.led);

  // 8. Pixel Sound Waves while Speaking
  if (isTalking && !paused) {
    const wPhase = Math.floor(t * 5) % 2;
    px(ctx, ox + 32, oy + 3, 1, 5, pal.led);
    px(ctx, ox + 31, oy + 2, 1, 1, pal.led);
    px(ctx, ox + 31, oy + 8, 1, 1, pal.led);
    if (wPhase === 1) {
      px(ctx, ox + 35, oy + 2, 1, 7, pal.led);
      px(ctx, ox + 34, oy + 1, 1, 1, pal.led);
      px(ctx, ox + 34, oy + 9, 1, 1, pal.led);
    }
  }
}

function drawMoodHud(ctx: CanvasRenderingContext2D, mood: OrcaMood, t: number, paused: boolean) {
  const floatY = paused ? 0 : Math.round(Math.sin(t * 2.4));

  if (mood === 'alert' || mood === 'blocked') {
    // 16-bit Pixel Crimson Warning Shield [!]
    const sx = 132;
    const sy = 44 + floatY;
    px(ctx, sx - 6, sy - 6, 13, 11, '#070a14');
    px(ctx, sx - 5, sy - 5, 11, 9, '#e94a32');
    px(ctx, sx - 3, sy + 4, 7, 3, '#e94a32');
    px(ctx, sx - 1, sy + 7, 3, 2, '#e94a32');
    px(ctx, sx - 5, sy - 5, 11, 1, '#ff917d');
    // Exclamation mark
    px(ctx, sx, sy - 3, 1, 5, '#ffffff');
    px(ctx, sx, sy + 3, 1, 1, '#ffffff');
  } else if (mood === 'happy') {
    // 16-bit Pixel Emerald Verified Badge [✓] + sparkles
    const sx = 132;
    const sy = 45 + floatY;
    px(ctx, sx - 6, sy - 6, 13, 13, '#070a14');
    px(ctx, sx - 5, sy - 5, 11, 11, '#3fbf7f');
    px(ctx, sx - 5, sy - 5, 11, 1, '#96f2c2');
    // Pixel checkmark
    px(ctx, sx - 3, sy, 1, 2, '#07140d');
    px(ctx, sx - 2, sy + 1, 1, 2, '#07140d');
    px(ctx, sx - 1, sy + 2, 1, 2, '#07140d');
    px(ctx, sx, sy + 1, 1, 2, '#07140d');
    px(ctx, sx + 1, sy, 1, 2, '#07140d');
    px(ctx, sx + 2, sy - 1, 1, 2, '#07140d');
    px(ctx, sx + 3, sy - 2, 1, 2, '#07140d');

    // Twinkling pixel + sparkle
    if (paused || Math.floor(t * 2) % 2 === 0) {
      px(ctx, 118, 52, 3, 1, '#ffe79e');
      px(ctx, 119, 51, 1, 3, '#ffe79e');
    }
  } else if (mood === 'scanning' && !paused) {
    // Stepped Pixel Sonar Rings
    const phase = (t * 0.9) % 1;
    const r = Math.round(10 + phase * 24);
    const alpha = Math.max(0.15, 1 - phase);
    ctx.fillStyle = `rgba(108, 228, 255, ${alpha.toFixed(2)})`;
    const cx = 114;
    const cy = 84;
    for (let deg = -55; deg <= 55; deg += 14) {
      const rad = (deg * Math.PI) / 180;
      const rx = Math.round(cx + Math.cos(rad) * r);
      const ry = Math.round(cy + Math.sin(rad) * r * 0.72);
      ctx.fillRect(rx, ry, 2, 2);
    }
  }
}

export function PixelOrcaScene({
  mood,
  isTalking,
  mouthLevel,
  paused = false,
  lookX = 0,
  lookY = 0,
  pokeTrigger = 0,
  className,
}: PixelOrcaSceneProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const propsRef = useRef({ mood, isTalking, mouthLevel, paused, lookX, lookY });
  const pokeBoostRef = useRef(0);
  const lastPokeRef = useRef(pokeTrigger);

  useEffect(() => {
    propsRef.current = { mood, isTalking, mouthLevel, paused, lookX, lookY };
  }, [mood, isTalking, mouthLevel, paused, lookX, lookY]);

  useEffect(() => {
    if (pokeTrigger !== lastPokeRef.current) {
      lastPokeRef.current = pokeTrigger;
      pokeBoostRef.current = 1.0;
    }
  }, [pokeTrigger]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.imageSmoothingEnabled = false;

    const renderFrame = (t: number) => {
      const { mood: m, isTalking: talking, mouthLevel: mouth, paused: isPaused, lookX: lx, lookY: ly } = propsRef.current;
      const pal = MOOD_COLORS[m];

      // 1. Midnight Winter Sky
      px(ctx, 0, 0, W, 52, '#0b0e18');
      px(ctx, 0, 52, W, 10, '#10172b');
      px(ctx, 0, 62, W, 10, '#17213d');

      // 2. Twinkling Pixel Stars (strictly < 1Hz gentle twinkle)
      for (let i = 0; i < STARS.length; i += 1) {
        const [sx, sy, speed, color] = STARS[i];
        const bright = isPaused ? i % 3 !== 0 : Math.sin(t * speed * Math.PI * 2 + i) > -0.35;
        if (bright) {
          px(ctx, sx, sy, i % 5 === 0 ? 2 : 1, i % 5 === 0 ? 2 : 1, color);
        } else {
          px(ctx, sx, sy, 1, 1, '#313d59');
        }
      }

      // 3. Animated Pixel Aurora Borealis Ribbons (2px stepped columns, echoing reference photo!)
      for (let x = 0; x < W; x += 2) {
        const waveA = Math.round(23 + Math.sin(x * 0.055 + t * 0.85) * 4 + Math.cos(x * 0.025 - t * 0.5) * 2);
        px(ctx, x, waveA - 2, 2, 2, pal.auroraA[0]);
        px(ctx, x, waveA, 2, 3, pal.auroraA[1]);
        px(ctx, x, waveA + 1, 2, 1, pal.auroraA[2]);

        const waveB = Math.round(33 + Math.cos(x * 0.048 - t * 0.72) * 4 + Math.sin(x * 0.03 + t * 0.4) * 2);
        px(ctx, x, waveB - 1, 2, 2, pal.auroraB[0]);
        px(ctx, x, waveB + 1, 2, 2, pal.auroraB[1]);
        if ((x + Math.floor(t * 4)) % 6 === 0) {
          px(ctx, x, waveB + 1, 2, 1, pal.auroraB[2]);
        }
      }

      // 4. Golden Pixel Crescent Moon (top-right, straight from reference photo!)
      const moonX = 132;
      const moonY = 7;
      for (let r = 0; r < MOON_BITMAP.length; r += 1) {
        const row = MOON_BITMAP[r];
        for (let c = 0; c < row.length; c += 1) {
          if (row[c] === '#') {
            const shade = c >= 4 || r >= 8 ? '#f5c76b' : '#ffe79e';
            px(ctx, moonX + c, moonY + r, 1, 1, shade);
          }
        }
      }

      // 5. Distant Snowy Mountain Ridge
      for (let mx = 0; mx < 64; mx += 2) {
        const mh = Math.max(0, 18 - Math.abs(mx - 34) * 0.65);
        if (mh > 0) {
          px(ctx, mx, 68 - mh, 2, mh, '#222e54');
          if (mh > 12) {
            px(ctx, mx, 68 - mh, 2, 2, '#9ec0e8');
          }
        }
      }

      // 6. Snowy Pine Trees & Cozy Wooden Cabin on the Horizon
      drawPine(ctx, 11, 71, 6);
      drawPine(ctx, 21, 72, 4);
      drawCabin(ctx, 27, 47, t);
      drawPine(ctx, 64, 71, 5);
      drawPine(ctx, 149, 71, 6);
      drawPine(ctx, 138, 72, 4);
      drawMiniSnowman(ctx, 123, 70);

      // 7. Snowy Arctic Bank Shoreline
      px(ctx, 0, 69, W, 3, '#eef6ff');
      px(ctx, 0, 72, W, 3, '#c3dffb');
      px(ctx, 0, 75, W, 2, '#8fb4e3');
      // Cabin snow path
      px(ctx, 37, 71, 10, 4, '#b5a38e');
      // Wooden fence on left
      px(ctx, 16, 67, 14, 1, '#6e4a38');
      px(ctx, 16, 69, 14, 1, '#57372a');
      px(ctx, 18, 66, 2, 5, '#6e4a38');
      px(ctx, 24, 66, 2, 5, '#6e4a38');

      // 8. Midnight Arctic Ocean Water + Shimmering Aurora Reflections
      px(ctx, 0, 77, W, H - 77, '#0c162c');
      px(ctx, 0, 96, W, H - 96, '#091122');

      for (let wy = 80; wy < H - 4; wy += 6) {
        const shift = isPaused ? 0 : Math.round(Math.sin(t * 1.4 + wy * 0.25) * 6);
        const rx = ((wy * 17 + shift) % (W - 24) + (W - 24)) % (W - 24);
        px(ctx, rx, wy, 12, 1, '#1f3661');
        px(ctx, (rx + 56) % (W - 14), wy + 2, 9, 1, wy < 94 ? pal.auroraA[1] : pal.auroraB[1]);
      }

      // 9. Animated 16-Bit Pixel-Art Aegis Orca!
      let leapOffset = 0;
      if (pokeBoostRef.current > 0.02 && !isPaused) {
        leapOffset = -Math.round(Math.sin(pokeBoostRef.current * Math.PI) * 8);
      }
      const bobY = isPaused ? 0 : Math.round(Math.sin(t * (talking ? 3.2 : 1.9)) * 2);
      const orcaX = 82;
      const orcaY = 88 + bobY + leapOffset;

      // Natural autonomous blink cycle (~every 3.8s for 140ms)
      const blinkCycle = t % 3.8;
      const isBlinking = !isPaused && blinkCycle > 3.66;

      drawOrca(ctx, orcaX, orcaY, t, m, talking, mouth, lx, ly, isBlinking, isPaused);

      // Playful pixel water splash droplets during click poke!
      if (pokeBoostRef.current > 0.08 && !isPaused) {
        const spread = Math.round((1 - pokeBoostRef.current) * 14);
        px(ctx, orcaX - 10 - spread, 98 - Math.round(pokeBoostRef.current * 6), 2, 2, '#eef6ff');
        px(ctx, orcaX + 26 + spread, 98 - Math.round(pokeBoostRef.current * 6), 2, 2, '#eef6ff');
        px(ctx, orcaX + 8, 97 - Math.round(pokeBoostRef.current * 9), 2, 2, '#c9e4ff');
      }

      // Crisp waterline foam lapping gently across Orca lower belly
      const foamShift = isPaused ? 0 : Math.round(Math.sin(t * 2.5) * 2);
      px(ctx, orcaX - 16 + foamShift, 99, 14, 1, '#78a3d9');
      px(ctx, orcaX + 4 - foamShift, 100, 22, 1, '#c9e4ff');
      px(ctx, orcaX + 24 + foamShift, 99, 9, 1, '#78a3d9');

      // 10. Floating Mood Pixel HUD Sprite
      drawMoodHud(ctx, m, t, isPaused);

      // 11. Gentle Pixel Snowfall
      for (let i = 0; i < SNOWFLAKES.length; i += 1) {
        const f = SNOWFLAKES[i];
        const sy = isPaused ? f.y : (f.y + t * f.speed) % (H - 8);
        const sx = isPaused ? f.x : (f.x + Math.sin(t * 1.1 + f.phase) * 3 + W) % W;
        px(ctx, sx, sy, f.size, f.size, i % 3 === 0 ? '#ffffff' : '#b8d7f5');
      }
    };

    if (paused) {
      renderFrame(1.4);
      return;
    }

    let rafId = 0;
    let lastDraw = 0;
    const startMs = performance.now();

    const loop = (now: number) => {
      rafId = window.requestAnimationFrame(loop);
      // Authentic crisp ~12 FPS retro pixel animation (ultra-low CPU/GPU!)
      if (now - lastDraw < 82) return;
      const dt = Math.min(0.15, (now - (lastDraw || now)) / 1000);
      lastDraw = now;
      if (pokeBoostRef.current > 0) {
        pokeBoostRef.current = Math.max(0, pokeBoostRef.current - dt * 1.9);
      }
      renderFrame((now - startMs) / 1000);
    };

    renderFrame(0);
    rafId = window.requestAnimationFrame(loop);

    return () => {
      if (rafId) window.cancelAnimationFrame(rafId);
    };
  }, [paused, mood, isTalking, mouthLevel, lookX, lookY]);

  return (
    <canvas
      ref={canvasRef}
      width={W}
      height={H}
      role="img"
      aria-label="Aegis Orca — 16-битная пиксельная сцена с северным сиянием и косаткой-стражем"
      className={className ? `pixel-art w-full h-full block object-cover ${className}` : 'pixel-art w-full h-full block object-cover'}
    />
  );
}
