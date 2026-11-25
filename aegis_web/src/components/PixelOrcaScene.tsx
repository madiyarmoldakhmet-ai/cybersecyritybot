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
  [7, 5, 0.35, '#f2f8ff'],
  [18, 11, 0.52, '#7da39e'],
  [29, 4, 0.28, '#ffd866'],
  [41, 14, 0.44, '#f2f8ff'],
  [52, 7, 0.61, '#94b8c4'],
  [65, 5, 0.33, '#f2f8ff'],
  [77, 13, 0.49, '#ffd866'],
  [88, 6, 0.41, '#7da39e'],
  [99, 10, 0.56, '#f2f8ff'],
  [112, 5, 0.37, '#94b8c4'],
  [119, 15, 0.46, '#f2f8ff'],
  [149, 7, 0.31, '#ffd866'],
  [154, 15, 0.54, '#94b8c4'],
  [12, 22, 0.42, '#7da39e'],
  [35, 25, 0.51, '#f2f8ff'],
  [58, 19, 0.38, '#7da39e'],
  [84, 21, 0.47, '#f2f8ff'],
  [105, 24, 0.34, '#ffd866'],
  [144, 24, 0.48, '#f2f8ff'],
  [153, 33, 0.39, '#7da39e'],
  [6, 36, 0.45, '#94b8c4'],
  [73, 34, 0.53, '#f2f8ff'],
  [116, 35, 0.36, '#94b8c4'],
];

const SNOWFLAKES: ReadonlyArray<{ x: number; y: number; speed: number; phase: number; size: number }> = [
  { x: 8, y: 10, speed: 6, phase: 0.2, size: 1 },
  { x: 18, y: 40, speed: 8, phase: 1.1, size: 1 },
  { x: 28, y: 6, speed: 7, phase: 2.3, size: 2 },
  { x: 39, y: 55, speed: 6, phase: 0.8, size: 1 },
  { x: 50, y: 24, speed: 9, phase: 3.0, size: 1 },
  { x: 61, y: 64, speed: 7, phase: 1.9, size: 1 },
  { x: 72, y: 16, speed: 8, phase: 4.1, size: 2 },
  { x: 84, y: 44, speed: 6, phase: 2.7, size: 1 },
  { x: 95, y: 9, speed: 8, phase: 0.5, size: 1 },
  { x: 106, y: 52, speed: 7, phase: 3.6, size: 1 },
  { x: 117, y: 20, speed: 9, phase: 1.4, size: 2 },
  { x: 129, y: 62, speed: 6, phase: 2.2, size: 1 },
  { x: 141, y: 14, speed: 7, phase: 3.9, size: 1 },
  { x: 152, y: 38, speed: 8, phase: 0.9, size: 2 },
  { x: 15, y: 78, speed: 7, phase: 2.1, size: 1 },
  { x: 66, y: 84, speed: 6, phase: 1.5, size: 1 },
  { x: 124, y: 86, speed: 8, phase: 0.4, size: 1 },
  { x: 147, y: 74, speed: 7, phase: 3.3, size: 1 },
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
    auroraA: ['#144d3c', '#238764', '#56e0a8'],
    auroraB: ['#4d1e2b', '#8f2c3a', '#ff6e61'],
    led: '#ffd866',
    iris: '#56e0a8',
  },
  thinking: {
    auroraA: ['#594115', '#b58426', '#ffd866'],
    auroraB: ['#144d3c', '#2b8a64', '#56e0a8'],
    led: '#ffd866',
    iris: '#ffd866',
  },
  scanning: {
    auroraA: ['#124659', '#248db0', '#6ce4ff'],
    auroraB: ['#164f44', '#2ca884', '#6ef0c2'],
    led: '#6ce4ff',
    iris: '#6ce4ff',
  },
  alert: {
    auroraA: ['#631717', '#c42e23', '#ff5e52'],
    auroraB: ['#4a1b30', '#87293f', '#ff8773'],
    led: '#ff5e52',
    iris: '#ff5e52',
  },
  blocked: {
    auroraA: ['#631717', '#c42e23', '#e93e32'],
    auroraB: ['#42192b', '#7a2538', '#e05348'],
    led: '#e93e32',
    iris: '#ff5e52',
  },
  happy: {
    auroraA: ['#17593d', '#2fa86e', '#63f0aa'],
    auroraB: ['#594115', '#bf912c', '#ffd866'],
    led: '#63f0aa',
    iris: '#63f0aa',
  },
};

function px(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, color: string) {
  ctx.fillStyle = color;
  ctx.fillRect(Math.round(x), Math.round(y), Math.round(w), Math.round(h));
}

function drawPine(ctx: CanvasRenderingContext2D, cx: number, baseY: number, tiers: number, decorated = false, t = 0) {
  px(ctx, cx - 1, baseY - 3, 3, 4, '#3d271c');
  for (let i = 0; i < tiers; i += 1) {
    const ty = baseY - 4 - i * 4;
    const half = Math.max(1, (tiers - i) * 2 + 1);
    px(ctx, cx - half, ty, half * 2 + 1, 3, '#134232');
    px(ctx, cx - half + 1, ty - 1, half * 2 - 1, 2, '#1f694e');
    px(ctx, cx - Math.max(1, half - 2), ty - 2, Math.max(2, (half - 2) * 2 + 1), 1, '#2d8a64');

    // Snow dusting on pine branches
    if (i % 2 === 1 || i === tiers - 1) {
      px(ctx, cx - Math.max(0, half - 1), ty - 1, Math.min(3, half), 1, '#e6f3ff');
      px(ctx, cx + Math.max(0, half - 2), ty, 2, 1, '#bedcf7');
    }

    // Christmas tree twinkling ornaments & fairy lights!
    if (decorated && half >= 3) {
      const blinkA = Math.floor(t * 1.4 + i) % 2 === 0;
      px(ctx, cx - half + 2, ty + 1, 1, 1, blinkA ? '#ff5247' : '#ffd866');
      px(ctx, cx + half - 2, ty, 1, 1, blinkA ? '#ffd866' : '#6ce4ff');
      if (half >= 6) {
        px(ctx, cx, ty + 1, 1, 1, blinkA ? '#6ce4ff' : '#ff5247');
      }
    }
  }

  if (decorated) {
    // Glowing golden Christmas tree star on top!
    const starY = baseY - 6 - tiers * 4;
    const starGlow = Math.floor(t * 1.6) % 2 === 0 ? '#fff2b2' : '#ffd866';
    px(ctx, cx, starY - 1, 1, 5, '#ffd866');
    px(ctx, cx - 2, starY + 1, 5, 1, '#ffd866');
    px(ctx, cx - 1, starY, 3, 3, starGlow);
  } else {
    px(ctx, cx, baseY - 4 - tiers * 4, 1, 2, '#f2f8ff');
  }
}

function drawPresent(ctx: CanvasRenderingContext2D, x: number, y: number, boxColor: string, ribbonColor: string) {
  px(ctx, x, y, 5, 4, boxColor);
  px(ctx, x + 2, y, 1, 4, ribbonColor);
  px(ctx, x, y + 1, 5, 1, ribbonColor);
  px(ctx, x + 1, y - 1, 3, 1, ribbonColor); // pixel bow
}

function drawCabin(ctx: CanvasRenderingContext2D, x: number, y: number, t: number) {
  // Cozy chimney smoke
  const smokeStep = Math.floor(t * 2) % 6;
  px(ctx, x + 23 + (smokeStep % 2), y - 6 - smokeStep, 2, 2, 'rgba(220, 238, 255, 0.55)');
  px(ctx, x + 24, y - 10 - ((smokeStep + 3) % 6), 2, 2, 'rgba(190, 220, 245, 0.35)');

  // Chimney with snow cap
  px(ctx, x + 22, y - 2, 4, 8, '#5e3936');
  px(ctx, x + 21, y - 3, 6, 1, '#f2f8ff');

  // Snowy pitched roof
  for (let row = 0; row < 10; row += 1) {
    const rx = x + 14 - row - 2;
    const rw = 6 + row * 2;
    px(ctx, rx, y + row, rw, 1, row % 2 === 0 ? '#3a2b4a' : '#2d213b');
    px(ctx, rx - 1, y + row, 2, 1, '#f2f8ff');
    px(ctx, rx + rw - 1, y + row, 2, 1, '#f2f8ff');
  }
  px(ctx, x + 13, y - 1, 4, 1, '#ffffff');

  // Pine garland + twinkling Christmas roof lights + icicles under eaves!
  px(ctx, x + 2, y + 10, 26, 1, '#1f6e4e');
  const lightPalette = ['#ff5247', '#ffd866', '#47d18c', '#6ce4ff'];
  const phase = Math.floor(t * 1.5);
  for (let ic = 3; ic <= 26; ic += 4) {
    px(ctx, x + ic, y + 11, 1, ic % 8 === 3 ? 3 : 2, '#c5e4ff');
    const bulbColor = lightPalette[(Math.floor(ic / 4) + phase) % lightPalette.length];
    px(ctx, x + ic + 2, y + 10, 1, 1, bulbColor);
  }

  // Warm wooden log cabin walls
  px(ctx, x + 3, y + 11, 24, 13, '#5e3a29');
  for (let logY = 13; logY <= 22; logY += 3) {
    px(ctx, x + 3, y + logY, 24, 1, '#42271b');
  }

  // Warm glowing fireplace windows
  const glow = Math.sin(t * 1.4) > -0.3 ? '#ffe58f' : '#f5b83d';
  px(ctx, x + 5, y + 14, 5, 5, '#2b1b16');
  px(ctx, x + 6, y + 15, 3, 3, glow);
  px(ctx, x + 7, y + 15, 1, 3, '#8f5920');

  px(ctx, x + 20, y + 14, 5, 5, '#2b1b16');
  px(ctx, x + 21, y + 15, 3, 3, glow);
  px(ctx, x + 22, y + 15, 1, 3, '#8f5920');

  // Door with Christmas holly wreath + crimson bow!
  px(ctx, x + 12, y + 15, 6, 9, '#2b1b16');
  px(ctx, x + 13, y + 16, 4, 8, '#3f251b');
  px(ctx, x + 14, y + 17, 2, 2, '#2d8a5b');
  px(ctx, x + 14, y + 16, 2, 1, '#e93e32');
  px(ctx, x + 16, y + 20, 1, 1, '#ffd866');
}

function drawMiniSnowman(ctx: CanvasRenderingContext2D, x: number, y: number, t: number, paused: boolean) {
  const wave = paused ? 0 : Math.floor(t * 2) % 2;
  // Twig arms (right arm waves cheerfully!)
  px(ctx, x - 2, y - 3, 2, 1, '#6e442f');
  px(ctx, x + 6, y - 3 - wave, 2, 1, '#6e442f');
  px(ctx, x + 7, y - 4 - wave, 1, 1, '#6e442f');

  px(ctx, x + 1, y - 9, 4, 2, '#182438'); // top hat
  px(ctx, x, y - 7, 6, 1, '#e93e32'); // red hat band
  px(ctx, x + 1, y - 6, 4, 3, '#f2f8ff'); // head
  px(ctx, x + 2, y - 5, 1, 1, '#081119'); // eye
  px(ctx, x + 4, y - 5, 2, 1, '#f28b30'); // carrot nose
  px(ctx, x + 1, y - 3, 5, 1, '#e93e32'); // red scarf
  px(ctx, x + 4, y - 2, 1, 2, '#e93e32'); // scarf tail
  px(ctx, x, y - 2, 6, 4, '#f2f8ff'); // body
  px(ctx, x + 2, y - 1, 1, 1, '#1d3647'); // coal button
}

function drawSantaSleigh(ctx: CanvasRenderingContext2D, t: number, paused: boolean) {
  // Subtle silhouette of Santa's sleigh + reindeer gliding slowly across the upper midnight sky
  const sx = paused ? 92 : Math.round(((t * 6) % 200) - 24);
  const sy = 15 + (paused ? 0 : Math.round(Math.sin(t * 1.4) * 1.5));
  if (sx < -20 || sx > W + 10) return;
  // Sleigh
  px(ctx, sx, sy + 2, 7, 2, '#e93e32');
  px(ctx, sx + 1, sy, 3, 2, '#ffd866'); // gift sack + Santa cap
  px(ctx, sx, sy + 4, 8, 1, '#ffd866'); // golden runner
  // Reins
  px(ctx, sx + 7, sy + 2, 4, 1, '#94b8b0');
  // Reindeer with glowing Rudolph nose!
  px(ctx, sx + 11, sy + 1, 4, 2, '#8c5a3c');
  px(ctx, sx + 14, sy, 2, 2, '#8c5a3c');
  px(ctx, sx + 16, sy + 1, 1, 1, '#ff5247'); // Rudolph red nose!
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
  const pomBounce = paused ? 0 : Math.round(Math.sin(t * 3.4));
  const angry = mood === 'alert' || mood === 'blocked';
  const happy = mood === 'happy';
  const scanning = mood === 'scanning' || mood === 'thinking';

  // 1. Tail peduncle & pixel flukes
  px(ctx, ox - 20, oy + 1 + tailShift, 8, 5, '#060c12');
  px(ctx, ox - 19, oy + 2 + tailShift, 7, 3, '#132133');
  px(ctx, ox - 26, oy - 5 + tailShift, 5, 3, '#060c12');
  px(ctx, ox - 25, oy - 4 + tailShift, 4, 2, '#1d344d');
  px(ctx, ox - 23, oy - 2 + tailShift, 5, 4, '#132133');
  px(ctx, ox - 25, oy + 5 + tailShift, 6, 3, '#060c12');
  px(ctx, ox - 24, oy + 5 + tailShift, 4, 2, '#132133');
  px(ctx, ox - 25, oy - 4 + tailShift, 2, 1, pal.led);

  // 2. Tall Iconic Dorsal Fin + Glowing Christmas LED Strip
  px(ctx, ox - 6, oy - 14, 3, 2, '#060c12');
  px(ctx, ox - 5, oy - 12, 5, 3, '#060c12');
  px(ctx, ox - 4, oy - 9, 8, 4, '#060c12');
  px(ctx, ox - 4, oy - 12, 3, 2, '#1c2f47');
  px(ctx, ox - 3, oy - 10, 5, 5, '#132133');
  px(ctx, ox - 4, oy - 12, 1, 2, pal.led);
  px(ctx, ox - 3, oy - 10, 1, 2, pal.led);
  px(ctx, ox - 2, oy - 8, 1, 2, pal.led);

  // 3. Sleek Pixel Orca Body & Rounded Head
  px(ctx, ox - 12, oy - 5, 36, 16, '#060c12');
  px(ctx, ox - 9, oy - 7, 30, 3, '#060c12');
  px(ctx, ox + 22, oy - 3, 6, 12, '#060c12');
  px(ctx, ox + 26, oy + 1, 4, 8, '#060c12');
  px(ctx, ox - 10, oy + 10, 34, 3, '#060c12');

  px(ctx, ox - 11, oy - 4, 34, 14, '#121e2e');
  px(ctx, ox - 8, oy - 6, 28, 3, '#182940');
  px(ctx, ox + 21, oy - 2, 6, 10, '#121e2e');
  px(ctx, ox + 25, oy + 2, 4, 6, '#121e2e');

  // Rim shine & saddle patch
  px(ctx, ox - 6, oy - 6, 20, 1, '#3b5b82');
  px(ctx, ox - 8, oy - 3, 6, 3, '#375273');

  // Snow-white Belly + Eye Patch
  px(ctx, ox - 9, oy + 7, 34, 4, '#f2f8ff');
  px(ctx, ox - 7, oy + 10, 29, 2, '#bedcf7');
  px(ctx, ox + 22, oy + 6, 6, 3, '#f2f8ff');
  px(ctx, ox - 10, oy + 5, 4, 3, '#f2f8ff');

  px(ctx, ox + 4, oy - 2, 8, 3, '#f2f8ff');
  px(ctx, ox + 5, oy - 3, 6, 1, '#ffffff');
  px(ctx, ox + 6, oy + 1, 5, 1, '#cce6ff');

  // 4. Cute 16-Bit PIXEL SANTA HAT on Aegis Orca's head!!
  px(ctx, ox + 10, oy - 9, 12, 3, '#ffffff'); // fluffy white fur brim
  px(ctx, ox + 11, oy - 7, 10, 1, '#cce6ff'); // brim bottom shade
  px(ctx, ox + 11, oy - 12, 9, 3, '#e93e32'); // red velvet cap
  px(ctx, ox + 12, oy - 14, 6, 2, '#e93e32');
  px(ctx, ox + 13, oy - 13, 3, 1, '#ff776b'); // cap highlight
  // Drooping Santa hat tip + bouncy white pom-pom!
  px(ctx, ox + 9, oy - 14, 4, 2, '#c42c21');
  px(ctx, ox + 7, oy - 13 + pomBounce, 3, 3, '#ffffff');
  px(ctx, ox + 8, oy - 11 + pomBounce, 2, 1, '#cce6ff');

  // 5. Cozy Red-and-Gold Christmas Scarf
  px(ctx, ox + 1, oy - 3, 3, 13, '#b8281c');
  px(ctx, ox + 2, oy - 2, 3, 11, '#e93e32');
  px(ctx, ox + 2, oy + 2, 3, 1, '#ffd866'); // golden festive stripe
  px(ctx, ox + 2, oy + 6, 3, 1, '#ffd866');
  // Fluttering scarf tail
  px(ctx, ox - 3, oy + 4 + scarfWave, 4, 3, '#e93e32');
  px(ctx, ox - 6, oy + 5 + scarfWave, 3, 2, '#c42c21');
  px(ctx, ox - 7, oy + 5 + scarfWave, 1, 2, '#ffd866');

  // 6. Expressive Pixel Eye
  const ex = ox + 16;
  const ey = oy;
  const dx = paused ? 0 : lookX > 0.25 ? 1 : lookX < -0.25 ? -1 : 0;
  const dy = paused ? 0 : lookY > 0.25 ? 1 : lookY < -0.25 ? -1 : 0;

  if (happy) {
    px(ctx, ex, ey + 1, 1, 1, '#f2f8ff');
    px(ctx, ex + 1, ey, 3, 1, '#f2f8ff');
    px(ctx, ex + 4, ey + 1, 1, 1, '#f2f8ff');
    px(ctx, ex + 1, ey + 1, 3, 1, pal.led);
    px(ctx, ex - 2, ey + 4, 3, 1, '#ff7d99');
  } else if (isBlinking) {
    px(ctx, ex, ey + 2, 5, 1, '#94b8b0');
  } else {
    px(ctx, ex, ey, 5, 5, '#04080d');
    px(ctx, ex + 1, ey + 1, 3, 3, pal.iris);
    px(ctx, ex + 2 + dx, ey + 2 + dy, 1, 1, '#04080d');
    px(ctx, ex + 1, ey + 1, 1, 1, '#ffffff');
  }

  if (angry) {
    px(ctx, ex - 1, ey - 2, 3, 1, '#ff6e61');
    px(ctx, ex + 2, ey - 1, 3, 1, '#ff6e61');
  }

  if (scanning) {
    px(ctx, ex - 1, ey - 1, 9, 5, 'rgba(108, 228, 255, 0.28)');
    px(ctx, ex - 1, ey - 1, 9, 1, pal.led);
    px(ctx, ex - 1, ey + 3, 9, 1, pal.led);
    px(ctx, ex + 1, ey + 1, 5, 1, '#ffffff');
  }

  // 7. Articulated Talking Pixel Mouth (lip-sync levels 0..3)
  const mx = ox + 20;
  const my = oy + 6;
  const level = isTalking ? Math.max(0, Math.min(3, mouthLevel)) : 0;
  if (level === 0) {
    if (happy) {
      px(ctx, mx, my, 2, 1, '#081119');
      px(ctx, mx + 2, my + 1, 4, 1, '#081119');
      px(ctx, mx + 6, my, 2, 1, '#081119');
    } else if (angry) {
      px(ctx, mx, my + 1, 2, 1, '#081119');
      px(ctx, mx + 2, my, 4, 1, '#081119');
      px(ctx, mx + 6, my + 1, 2, 1, '#081119');
    } else {
      px(ctx, mx, my, 7, 1, '#081119');
      px(ctx, mx + 7, my - 1, 1, 1, '#081119');
    }
  } else {
    const mh = level === 1 ? 2 : level === 2 ? 4 : 5;
    px(ctx, mx, my - 1, 8, mh + 1, '#260b1c');
    px(ctx, mx + 1, my - 1, 6, 1, '#ffffff');
    if (mh >= 2) {
      px(ctx, mx + 2, my + mh - 2, 4, 1, '#ff738f');
    }
  }

  // 8. Front Pectoral Fin
  px(ctx, ox + 6, oy + 9 + finShift, 6, 6, '#060c12');
  px(ctx, ox + 7, oy + 9 + finShift, 4, 5, '#172940');
  px(ctx, ox + 8, oy + 10 + finShift, 1, 3, pal.led);

  // 9. Pixel Speech Waves
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
    const sx = 132;
    const sy = 44 + floatY;
    px(ctx, sx - 6, sy - 6, 13, 11, '#060c12');
    px(ctx, sx - 5, sy - 5, 11, 9, '#e93e32');
    px(ctx, sx - 3, sy + 4, 7, 3, '#e93e32');
    px(ctx, sx - 1, sy + 7, 3, 2, '#e93e32');
    px(ctx, sx - 5, sy - 5, 11, 1, '#ffd866');
    px(ctx, sx, sy - 3, 1, 5, '#ffffff');
    px(ctx, sx, sy + 3, 1, 1, '#ffffff');
  } else if (mood === 'happy') {
    const sx = 132;
    const sy = 45 + floatY;
    px(ctx, sx - 6, sy - 6, 13, 13, '#060c12');
    px(ctx, sx - 5, sy - 5, 11, 11, '#2f9e66');
    px(ctx, sx - 5, sy - 5, 11, 1, '#ffd866');
    px(ctx, sx - 3, sy, 1, 2, '#ffffff');
    px(ctx, sx - 2, sy + 1, 1, 2, '#ffffff');
    px(ctx, sx - 1, sy + 2, 1, 2, '#ffffff');
    px(ctx, sx, sy + 1, 1, 2, '#ffffff');
    px(ctx, sx + 1, sy, 1, 2, '#ffffff');
    px(ctx, sx + 2, sy - 1, 1, 2, '#ffffff');
    px(ctx, sx + 3, sy - 2, 1, 2, '#ffffff');
    if (paused || Math.floor(t * 2) % 2 === 0) {
      px(ctx, 118, 52, 3, 1, '#ffd866');
      px(ctx, 119, 51, 1, 3, '#ffd866');
    }
  } else if (mood === 'scanning' && !paused) {
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

      // 1. Christmas Eve Deep Midnight Sky
      px(ctx, 0, 0, W, 52, '#081119');
      px(ctx, 0, 52, W, 10, '#0e1c26');
      px(ctx, 0, 62, W, 10, '#142936');

      // 2. Twinkling Starlight (<1Hz)
      for (let i = 0; i < STARS.length; i += 1) {
        const [sx, sy, speed, color] = STARS[i];
        const bright = isPaused ? i % 3 !== 0 : Math.sin(t * speed * Math.PI * 2 + i) > -0.35;
        if (bright) {
          px(ctx, sx, sy, i % 5 === 0 ? 2 : 1, i % 5 === 0 ? 2 : 1, color);
        } else {
          px(ctx, sx, sy, 1, 1, '#29404a');
        }
      }

      // 3. Festive Christmas Aurora Ribbons
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

      // 4. Subtle Santa's Sleigh & Rudolph gliding across the sky!
      drawSantaSleigh(ctx, t, isPaused);

      // 5. Golden Pixel Crescent Moon
      const moonX = 132;
      const moonY = 7;
      for (let r = 0; r < MOON_BITMAP.length; r += 1) {
        const row = MOON_BITMAP[r];
        for (let c = 0; c < row.length; c += 1) {
          if (row[c] === '#') {
            const shade = c >= 4 || r >= 8 ? '#f5b83d' : '#ffd866';
            px(ctx, moonX + c, moonY + r, 1, 1, shade);
          }
        }
      }

      // 6. Distant Snowy Mountain Ridge
      for (let mx = 0; mx < 64; mx += 2) {
        const mh = Math.max(0, 18 - Math.abs(mx - 34) * 0.65);
        if (mh > 0) {
          px(ctx, mx, 68 - mh, 2, mh, '#1a3040');
          if (mh > 12) {
            px(ctx, mx, 68 - mh, 2, 2, '#a7cde8');
          }
        }
      }

      // 7. Snowy Christmas Pines, Cozy Decorated Cabin, Big Lit Christmas Tree & Snowman!
      drawPine(ctx, 10, 71, 6, false, t);
      drawCabin(ctx, 22, 47, t);
      // Centerpiece Decorated Pixel Christmas Tree with Star & Lights!
      drawPine(ctx, 64, 71, 6, true, t);
      drawPine(ctx, 149, 71, 6, true, t);
      drawPine(ctx, 136, 72, 4, false, t);
      drawMiniSnowman(ctx, 121, 70, t, isPaused);

      // 8. Snowy Arctic Bank Shoreline + Wrapped Christmas Presents under the Tree!
      px(ctx, 0, 69, W, 3, '#f2f8ff');
      px(ctx, 0, 72, W, 3, '#c8e4fc');
      px(ctx, 0, 75, W, 2, '#91bbe3');
      px(ctx, 32, 71, 10, 4, '#b8a28b'); // cabin path
      // Fence
      px(ctx, 12, 67, 13, 1, '#6e442f');
      px(ctx, 12, 69, 13, 1, '#543322');
      px(ctx, 14, 66, 2, 5, '#6e442f');
      px(ctx, 20, 66, 2, 5, '#6e442f');
      // 3 Colorful Wrapped Pixel Christmas Presents beneath the decorated tree!
      drawPresent(ctx, 56, 67, '#e93e32', '#ffd866');
      drawPresent(ctx, 62, 68, '#2d8a5b', '#ff5247');
      drawPresent(ctx, 68, 67, '#3498db', '#ffd866');

      // 9. Midnight Winter Water + Shimmering Christmas Light Reflections
      px(ctx, 0, 77, W, H - 77, '#0a1622');
      px(ctx, 0, 96, W, H - 96, '#071019');

      for (let wy = 80; wy < H - 4; wy += 6) {
        const shift = isPaused ? 0 : Math.round(Math.sin(t * 1.4 + wy * 0.25) * 6);
        const rx = ((wy * 17 + shift) % (W - 24) + (W - 24)) % (W - 24);
        px(ctx, rx, wy, 12, 1, '#1a384a');
        px(ctx, (rx + 56) % (W - 14), wy + 2, 9, 1, wy < 94 ? pal.auroraA[1] : pal.auroraB[1]);
      }

      // 10. Animated 16-Bit Christmas Santa-Hat Aegis Orca!
      let leapOffset = 0;
      if (pokeBoostRef.current > 0.02 && !isPaused) {
        leapOffset = -Math.round(Math.sin(pokeBoostRef.current * Math.PI) * 8);
      }
      const bobY = isPaused ? 0 : Math.round(Math.sin(t * (talking ? 3.2 : 1.9)) * 2);
      const orcaX = 82;
      const orcaY = 89 + bobY + leapOffset;

      const blinkCycle = t % 3.8;
      const isBlinking = !isPaused && blinkCycle > 3.66;

      drawOrca(ctx, orcaX, orcaY, t, m, talking, mouth, lx, ly, isBlinking, isPaused);

      if (pokeBoostRef.current > 0.08 && !isPaused) {
        const spread = Math.round((1 - pokeBoostRef.current) * 14);
        px(ctx, orcaX - 10 - spread, 99 - Math.round(pokeBoostRef.current * 6), 2, 2, '#f2f8ff');
        px(ctx, orcaX + 26 + spread, 99 - Math.round(pokeBoostRef.current * 6), 2, 2, '#f2f8ff');
        px(ctx, orcaX + 8, 98 - Math.round(pokeBoostRef.current * 9), 2, 2, '#ffd866');
      }

      const foamShift = isPaused ? 0 : Math.round(Math.sin(t * 2.5) * 2);
      px(ctx, orcaX - 16 + foamShift, 100, 14, 1, '#79a8c9');
      px(ctx, orcaX + 4 - foamShift, 101, 22, 1, '#d1e9ff');
      px(ctx, orcaX + 24 + foamShift, 100, 9, 1, '#79a8c9');

      // 11. Floating Mood Pixel HUD Sprite
      drawMoodHud(ctx, m, t, isPaused);

      // 12. Gentle Christmas Eve Pixel Snowfall
      for (let i = 0; i < SNOWFLAKES.length; i += 1) {
        const f = SNOWFLAKES[i];
        const sy = isPaused ? f.y : (f.y + t * f.speed) % (H - 8);
        const sx = isPaused ? f.x : (f.x + Math.sin(t * 1.1 + f.phase) * 3 + W) % W;
        px(ctx, sx, sy, f.size, f.size, i % 4 === 0 ? '#ffffff' : '#cce6ff');
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
      aria-label="Aegis Orca — 16-битная рождественская пиксельная сцена с ёлкой, подарками, снеговиком и косаткой в шапке Санты"
      className={className ? `pixel-art w-full h-full block object-cover ${className}` : 'pixel-art w-full h-full block object-cover'}
    />
  );
}
