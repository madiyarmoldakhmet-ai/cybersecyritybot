'use client';

import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrcaMood } from '@/components/OrcaRigSvg';
import { cn } from '@/lib/utils';

interface Orca3DCanvasProps {
  mood: OrcaMood;
  isTalking: boolean;
  /** 0 = closed, 1 = soft, 2 = medium, 3 = wide open */
  mouthLevel: number;
  paused?: boolean;
  lookX?: number;
  lookY?: number;
  pokeTrigger?: number;
  className?: string;
}

const MOOD_COLORS: Record<
  OrcaMood,
  {
    accent: number;
    rim: number;
    fill: number;
    bgTop: string;
    bgBottom: string;
  }
> = {
  idle: {
    accent: 0x38bdf8,
    rim: 0x7dd3fc,
    fill: 0x2563eb,
    bgTop: '#0d2842',
    bgBottom: '#061221',
  },
  thinking: {
    accent: 0xf59e0b,
    rim: 0xfde68a,
    fill: 0xb45309,
    bgTop: '#261c0a',
    bgBottom: '#0c0905',
  },
  scanning: {
    accent: 0x22d3ee,
    rim: 0x67e8f9,
    fill: 0x0284c7,
    bgTop: '#092c3f',
    bgBottom: '#04121d',
  },
  alert: {
    accent: 0xff5436,
    rim: 0xff7b63,
    fill: 0xb91c1c,
    bgTop: '#2b0d10',
    bgBottom: '#100507',
  },
  blocked: {
    accent: 0xe94a32,
    rim: 0xff735d,
    fill: 0x991b1b,
    bgTop: '#2a0d11',
    bgBottom: '#100507',
  },
  happy: {
    accent: 0x3fbf7f,
    rim: 0x6ee7b7,
    fill: 0x059669,
    bgTop: '#0a2b20',
    bgBottom: '#05120e',
  },
};

function smoothstep(edge0: number, edge1: number, x: number): number {
  const t = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0)));
  return t * t * (3 - 2 * t);
}

/**
 * Evaluates anatomical killer whale (Orcinus orca) cross-section along normalized body length t in [0..1]:
 * t = 0: tip of snout (+Z = +1.72), t = 1: tail peduncle junction (-Z = -2.02)
 */
function sampleOrcaSpine(t: number) {
  const z = 1.72 - t * 3.74;

  // Gentle hydro-dynamic arched spine curve
  const spineY =
    0.09 * Math.sin(t * Math.PI * 0.92) -
    0.05 * smoothstep(0.65, 1.0, t) -
    0.06 * (1 - smoothstep(0.0, 0.2, t));

  // Width (half-beam rx): rounded bulbous melon nose -> broad muscular chest -> narrow vertical tail keel
  const noseW = Math.pow(Math.sin(Math.min(1, t / 0.34) * (Math.PI * 0.5)), 0.62);
  const tailW = Math.pow(Math.max(0.0001, 1 - Math.max(0, (t - 0.34) / 0.66)), 1.38);
  const rx = 0.015 + 0.54 * noseW * tailW;

  // Dorsal height (ryTop): prominent domed melon forehead + sleek arch behind dorsal
  const noseTop = Math.pow(Math.sin(Math.min(1, t / 0.32) * (Math.PI * 0.5)), 0.52);
  const melonBump = 0.08 * Math.exp(-Math.pow((t - 0.13) / 0.09, 2));
  const tailTop = Math.pow(Math.max(0.0001, 1 - Math.max(0, (t - 0.32) / 0.68)), 1.12);
  const ryTop = 0.015 + (0.48 * noseTop + melonBump) * tailTop;

  // Ventral depth (ryBot): slightly fuller chest, smooth taper to peduncle keel
  const noseBot = Math.pow(Math.sin(Math.min(1, t / 0.30) * (Math.PI * 0.5)), 0.68);
  const tailBot = Math.pow(Math.max(0.0001, 1 - Math.max(0, (t - 0.30) / 0.70)), 1.24);
  const ryBot = 0.015 + 0.43 * noseBot * tailBot;

  return { z, spineY, rx, ryTop, ryBot };
}

/**
 * Generates high-resolution 1024x1024 UV skin texture for the killer whale.
 * UV convention on the lofted body:
 *   u in [0..1] around cross-section: u=0.0 (+X right flank), u=0.25 (+Y dorsal ridge),
 *   u=0.5 (-X left flank), u=0.75 (-Y ventral belly), u=1.0 (+X right flank)
 *   v in [0..1] along body: v=0 (snout tip) -> v=1 (tail junction)
 */
function createOrcaSkinTexture(): THREE.CanvasTexture {
  const size = 1024;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  if (!ctx) return new THREE.CanvasTexture(canvas);

  // Deep wet satin obsidian-slate base gradient (readable 3D form against ocean backdrop)
  const baseGrad = ctx.createLinearGradient(0, 0, 0, size);
  baseGrad.addColorStop(0, '#182436');
  baseGrad.addColorStop(0.4, '#101928');
  baseGrad.addColorStop(1, '#090f19');
  ctx.fillStyle = baseGrad;
  ctx.fillRect(0, 0, size, size);

  // Helper to paint in (u, v) coordinates with horizontal wrap-around so seams are invisible
  const drawWrapped = (fn: (offsetX: number) => void) => {
    fn(0);
    fn(-size);
    fn(size);
  };

  // 1. Classic Orca Saddle Patch (smoky silver-slate mantle behind dorsal fin, centered at dorsal u=0.25)
  ctx.save();
  ctx.filter = 'blur(14px)';
  const saddleGrad = ctx.createRadialGradient(0.25 * size, 0.53 * size, 12, 0.25 * size, 0.54 * size, 145);
  saddleGrad.addColorStop(0, 'rgba(148, 174, 204, 0.52)');
  saddleGrad.addColorStop(0.65, 'rgba(104, 130, 162, 0.28)');
  saddleGrad.addColorStop(1, 'rgba(104, 130, 162, 0)');
  ctx.fillStyle = saddleGrad;
  ctx.beginPath();
  ctx.ellipse(0.25 * size, 0.54 * size, 155, 86, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();

  // 2. Snow-White Ventral Belly + Iconic Sweeping Flank Patches (centered at belly u=0.75)
  ctx.save();
  ctx.filter = 'blur(3.5px)';
  const bellyGrad = ctx.createLinearGradient(0, 0, 0, size);
  bellyGrad.addColorStop(0, '#ffffff');
  bellyGrad.addColorStop(0.6, '#f1f7ff');
  bellyGrad.addColorStop(1, '#dbeafe');
  ctx.fillStyle = bellyGrad;

  // Main continuous ventral belly from chin (v=0.05) to pre-tail (v=0.86)
  ctx.beginPath();
  ctx.moveTo(0.75 * size, 0.04 * size);
  // Right flank edge (from belly u=0.75 upward toward flank u=0.90..0.99)
  ctx.bezierCurveTo(0.87 * size, 0.07 * size, 0.88 * size, 0.22 * size, 0.85 * size, 0.36 * size);
  // Waist near pectoral fin
  ctx.bezierCurveTo(0.83 * size, 0.45 * size, 0.85 * size, 0.52 * size, 0.94 * size, 0.57 * size);
  // Iconic sweeping upward white flank lobe!
  ctx.bezierCurveTo(1.01 * size, 0.62 * size, 1.00 * size, 0.72 * size, 0.89 * size, 0.74 * size);
  // Taper cleanly down toward tail peduncle
  ctx.bezierCurveTo(0.83 * size, 0.78 * size, 0.79 * size, 0.84 * size, 0.75 * size, 0.86 * size);
  // Mirror to left flank edge (u=0.75 toward u=0.50)
  ctx.bezierCurveTo(0.71 * size, 0.84 * size, 0.67 * size, 0.78 * size, 0.61 * size, 0.74 * size);
  ctx.bezierCurveTo(0.50 * size, 0.72 * size, 0.49 * size, 0.62 * size, 0.56 * size, 0.57 * size);
  ctx.bezierCurveTo(0.65 * size, 0.52 * size, 0.67 * size, 0.45 * size, 0.65 * size, 0.36 * size);
  ctx.bezierCurveTo(0.62 * size, 0.22 * size, 0.63 * size, 0.07 * size, 0.75 * size, 0.04 * size);
  ctx.closePath();
  drawWrapped((ox) => {
    ctx.save();
    ctx.translate(ox, 0);
    ctx.fill();
    ctx.restore();
  });
  ctx.restore();

  // 3. Iconic Snow-White Post-Ocular Eye Patches (bold classic killer whale angled oval above both eyes!)
  ctx.save();
  ctx.filter = 'blur(2.5px)';
  ctx.fillStyle = '#ffffff';
  drawWrapped((ox) => {
    ctx.save();
    ctx.translate(ox + 0.088 * size, 0.245 * size);
    ctx.rotate(-0.16);
    ctx.beginPath();
    ctx.ellipse(0, 0, 40, 94, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  });
  drawWrapped((ox) => {
    ctx.save();
    ctx.translate(ox + 0.412 * size, 0.245 * size);
    ctx.rotate(0.16);
    ctx.beginPath();
    ctx.ellipse(0, 0, 40, 94, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  });
  ctx.restore();

  const tex = new THREE.CanvasTexture(canvas);
  tex.flipY = false; // CRITICAL: keep v=0 at snout (top of canvas) and v=1 at tail (bottom of canvas)!
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.wrapS = THREE.RepeatWrapping;
  tex.wrapT = THREE.ClampToEdgeWrapping;
  tex.anisotropy = 4;
  tex.needsUpdate = true;
  return tex;
}

/**
 * Builds the smooth lofted 3D body geometry (with rest positions stored for real-time swimming spine wave).
 */
function buildOrcaBodyGeometry() {
  const rings = 64;
  const segs = 48;
  const positions: number[] = [];
  const uvs: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i <= rings; i++) {
    const t = i / rings;
    const { z, spineY, rx, ryTop, ryBot } = sampleOrcaSpine(t);

    for (let j = 0; j <= segs; j++) {
      const u = j / segs;
      const theta = u * Math.PI * 2;
      const cosT = Math.cos(theta);
      const sinT = Math.sin(theta);

      let x = cosT * rx;
      let y = spineY + sinT * (sinT >= 0 ? ryTop : ryBot);

      // Slight dorsal keel crispness along tail peduncle
      if (t > 0.55 && Math.abs(cosT) < 0.45) {
        const keel = smoothstep(0.55, 0.95, t) * (1 - Math.abs(cosT) / 0.45) * 0.055;
        y += sinT >= 0 ? keel : -keel * 0.7;
      }

      // Recess underside of snout gently so the articulated lower jaw sits flush when closed
      if (t > 0.03 && t < 0.22 && sinT < -0.35) {
        const jawMask =
          smoothstep(0.03, 0.08, t) *
          (1 - smoothstep(0.17, 0.22, t)) *
          smoothstep(-0.35, -0.72, sinT);
        y += jawMask * 0.095;
        x *= 1 - jawMask * 0.06;
      }

      positions.push(x, y, z);
      uvs.push(u, t);
    }
  }

  const stride = segs + 1;
  for (let i = 0; i < rings; i++) {
    for (let j = 0; j < segs; j++) {
      const a = i * stride + j;
      const b = (i + 1) * stride + j;
      const c = (i + 1) * stride + (j + 1);
      const d = i * stride + (j + 1);
      // Outward-facing CCW winding
      indices.push(a, d, b);
      indices.push(b, d, c);
    }
  }

  const geom = new THREE.BufferGeometry();
  const posArr = new Float32Array(positions);
  geom.setAttribute('position', new THREE.BufferAttribute(posArr, 3));
  geom.setAttribute('uv', new THREE.BufferAttribute(new Float32Array(uvs), 2));
  geom.setIndex(indices);
  geom.computeVertexNormals();

  return { geom, restPositions: new Float32Array(posArr) };
}

/**
 * Builds an articulated lower jaw mesh that nests flush inside the underside of the snout
 * and pivots smoothly open around (0, -0.17, 0.94) when the Orca talks.
 */
function buildLowerJawGeometry(): THREE.BufferGeometry {
  const rings = 20;
  const segs = 24;
  const positions: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i <= rings; i++) {
    const t = i / rings; // 0 = rounded chin tip (front), 1 = jaw hinge (back)
    const z = 0.62 - t * 0.66; // local Z relative to hinge pivot at z=0.94 -> tip at z=1.56
    const width = 0.26 * Math.pow(Math.sin(Math.min(1, t / 0.85) * (Math.PI * 0.5)), 0.58) * (1 - 0.1 * t);
    const depth = 0.115 * Math.sin(Math.max(0.05, t) * Math.PI * 0.84);

    for (let j = 0; j <= segs; j++) {
      const a = (j / segs) * Math.PI * 2;
      const ca = Math.cos(a);
      const sa = Math.sin(a);
      const x = ca * width;
      // Flat top tongue bed, smooth rounded snow-white chin underneath
      const y = sa >= 0 ? sa * depth * 0.2 : sa * depth;
      positions.push(x, y, z);
    }
  }

  const stride = segs + 1;
  for (let i = 0; i < rings; i++) {
    for (let j = 0; j < segs; j++) {
      const a = i * stride + j;
      const b = (i + 1) * stride + j;
      const c = (i + 1) * stride + (j + 1);
      const d = i * stride + (j + 1);
      indices.push(a, d, b);
      indices.push(b, d, c);
    }
  }

  const geom = new THREE.BufferGeometry();
  geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  geom.setIndex(indices);
  geom.computeVertexNormals();
  return geom;
}

/**
 * Builds an organic NACA-airfoil curved Orca dorsal fin rising proudly & sweeping back.
 */
function buildDorsalFinGeometry(): THREE.BufferGeometry {
  const rows = 24;
  const cols = 20;
  const positions: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i <= rows; i++) {
    const h = i / rows; // 0 = buried in spine, 1 = curved fin tip
    const y = -0.10 + h * 0.98;
    // Graceful backward sweep
    const centerZ = 0.04 - Math.pow(h, 1.38) * 0.62;
    // Chord narrows smoothly to rounded tip
    const chord = 0.72 * Math.pow(Math.max(0.02, 1 - h * 0.92), 0.72);
    const maxThick = 0.085 * Math.pow(Math.max(0.04, 1 - h * 0.93), 0.85);

    for (let j = 0; j <= cols; j++) {
      const a = (j / cols) * Math.PI * 2;
      // Hydrofoil cross-section: thick rounded leading edge (+Z), crisp tapered trailing edge (-Z)
      const s = 0.5 * (1 + Math.cos(a)); // 1 at leading edge, 0 at trailing edge
      const z = centerZ + (s - 0.45) * chord;
      const foilThickness = Math.sin(a) * maxThick * Math.pow(Math.max(0.01, s), 0.45);
      positions.push(foilThickness, y, z);
    }
  }

  const stride = cols + 1;
  for (let i = 0; i < rows; i++) {
    for (let j = 0; j < cols; j++) {
      const a = i * stride + j;
      const b = (i + 1) * stride + j;
      const c = (i + 1) * stride + (j + 1);
      const d = i * stride + (j + 1);
      indices.push(a, b, d);
      indices.push(b, c, d);
    }
  }

  const geom = new THREE.BufferGeometry();
  geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  geom.setIndex(indices);
  geom.computeVertexNormals();
  return geom;
}

/**
 * Builds the iconic rounded paddle-shaped pectoral fin of a killer whale (side = +1 right, -1 left).
 */
function buildPectoralFinGeometry(side: 1 | -1): THREE.BufferGeometry {
  const rows = 20;
  const cols = 20;
  const positions: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i <= rows; i++) {
    const s = i / rows; // 0 = shoulder joint, 1 = broad rounded paddle tip
    const span = s * 0.86;
    const x = side * span;
    const y = -Math.pow(s, 1.2) * 0.34;
    const centerZ = -Math.pow(s, 1.35) * 0.32;
    // Broad paddle silhouette (wide through mid-fin, gently rounded tip)
    const chord = 0.48 * Math.sin(Math.min(1, 0.14 + s * 0.86) * Math.PI * 0.94);
    const thick = 0.058 * Math.pow(Math.max(0.04, 1 - s * 0.86), 0.72);

    for (let j = 0; j <= cols; j++) {
      const a = (j / cols) * Math.PI * 2;
      const u = 0.5 * (1 + Math.cos(a));
      const z = centerZ + (u - 0.48) * chord;
      const dy = Math.sin(a) * thick * Math.pow(Math.max(0.02, u), 0.4);
      positions.push(x, y + dy, z);
    }
  }

  const stride = cols + 1;
  for (let i = 0; i < rows; i++) {
    for (let j = 0; j < cols; j++) {
      const a = i * stride + j;
      const b = (i + 1) * stride + j;
      const c = (i + 1) * stride + (j + 1);
      const d = i * stride + (j + 1);
      if (side === 1) {
        indices.push(a, d, b);
        indices.push(b, d, c);
      } else {
        indices.push(a, b, d);
        indices.push(b, c, d);
      }
    }
  }

  const geom = new THREE.BufferGeometry();
  geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  geom.setIndex(indices);
  geom.computeVertexNormals();
  return geom;
}

/**
 * Builds a single crescent tail fluke lobe (side = +1 right, -1 left) with a sharp trailing crescent & median notch.
 */
function buildTailFlukeLobe(side: 1 | -1): THREE.BufferGeometry {
  const rows = 20;
  const cols = 18;
  const positions: number[] = [];
  const indices: number[] = [];

  for (let i = 0; i <= rows; i++) {
    const s = i / rows; // 0 = peduncle root, 1 = sweeping crescent wingtip
    const x = side * (0.02 + s * 0.78);
    // Sweeps dramatically backward into twin crescent flukes
    const centerZ = -Math.pow(s, 1.32) * 0.44;
    const chord = 0.50 * Math.pow(Math.max(0.02, 1 - Math.pow(s, 1.55)), 0.75);
    const thick = 0.052 * Math.pow(Math.max(0.03, 1 - s * 0.9), 0.85);
    // Slight elegant upward curl at tips
    const yCurl = Math.pow(s, 2.0) * 0.05;

    for (let j = 0; j <= cols; j++) {
      const a = (j / cols) * Math.PI * 2;
      const u = 0.5 * (1 + Math.cos(a));
      const z = centerZ + (u - 0.5) * chord;
      const y = yCurl + Math.sin(a) * thick * Math.pow(Math.max(0.02, u), 0.42);
      positions.push(x, y, z);
    }
  }

  const stride = cols + 1;
  for (let i = 0; i < rows; i++) {
    for (let j = 0; j < cols; j++) {
      const a = i * stride + j;
      const b = (i + 1) * stride + j;
      const c = (i + 1) * stride + (j + 1);
      const d = i * stride + (j + 1);
      if (side === 1) {
        indices.push(a, d, b);
        indices.push(b, d, c);
      } else {
        indices.push(a, b, d);
        indices.push(b, c, d);
      }
    }
  }

  const geom = new THREE.BufferGeometry();
  geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  geom.setIndex(indices);
  geom.computeVertexNormals();
  return geom;
}

export function Orca3DCanvas({
  mood,
  isTalking,
  mouthLevel,
  paused = false,
  lookX = 0,
  lookY = 0,
  pokeTrigger = 0,
  className,
}: Orca3DCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [webglFailed, setWebglFailed] = useState(false);

  // Live reactive props ref so the 60fps WebGL loop updates smoothly with ZERO scene rebuilds
  const propsRef = useRef({ mood, isTalking, mouthLevel, paused, lookX, lookY });
  const pokeEnergyRef = useRef(0);
  const lastPokeRef = useRef(pokeTrigger);

  useEffect(() => {
    propsRef.current = { mood, isTalking, mouthLevel, paused, lookX, lookY };
    if (pokeTrigger !== lastPokeRef.current) {
      lastPokeRef.current = pokeTrigger;
      pokeEnergyRef.current = 1.0;
    }
  }, [mood, isTalking, mouthLevel, paused, lookX, lookY, pokeTrigger]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        alpha: true,
        powerPreference: 'high-performance',
      });
    } catch {
      queueMicrotask(() => setWebglFailed(true));
      return;
    }

    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.24;
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    renderer.domElement.style.display = 'block';
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();

    // Cinematic 3/4 wide-profile camera from port side (-X) with comfortable framing margin on nose & tail
    const camera = new THREE.PerspectiveCamera(33, 1, 0.1, 45);
    camera.position.set(-4.7, 1.08, 3.15);
    camera.lookAt(0.0, 0.08, -0.08);

    // === STUDIO 3-POINT + UNDERWATER RIM LIGHTING ===
    const hemiLight = new THREE.HemisphereLight(0xd6f2ff, 0x0b1f38, 1.4);
    scene.add(hemiLight);

    const keyLight = new THREE.DirectionalLight(0xf4faff, 2.25);
    keyLight.position.set(-4.5, 5.4, 4.2);
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x7dd3fc, 2.9);
    rimLight.position.set(4.2, 3.2, -3.0);
    scene.add(rimLight);

    const bellyBounce = new THREE.PointLight(0x2563eb, 1.8, 12);
    bellyBounce.position.set(-1.6, -2.5, 1.8);
    scene.add(bellyBounce);

    // === ORCA MASTER RIG GROUP ===
    const orcaRoot = new THREE.Group();
    orcaRoot.rotation.y = -0.06;
    scene.add(orcaRoot);

    // 1. Satin-Wet Glossy Skin & Fin Materials (soft studio clearcoat = Pixar/Spline finish!)
    const skinTex = createOrcaSkinTexture();
    const bodyMat = new THREE.MeshPhysicalMaterial({
      map: skinTex,
      roughness: 0.28,
      metalness: 0.04,
      clearcoat: 0.92,
      clearcoatRoughness: 0.24,
      reflectivity: 0.85,
    });

    const finMat = new THREE.MeshPhysicalMaterial({
      color: 0x121d30,
      roughness: 0.26,
      metalness: 0.05,
      clearcoat: 0.92,
      clearcoatRoughness: 0.22,
    });

    const whiteJawMat = new THREE.MeshPhysicalMaterial({
      color: 0xf4f8ff,
      roughness: 0.28,
      metalness: 0.02,
      clearcoat: 0.88,
      clearcoatRoughness: 0.24,
    });

    const mouthInnerMat = new THREE.MeshStandardMaterial({
      color: 0x260917,
      roughness: 0.58,
    });

    const tongueMat = new THREE.MeshStandardMaterial({
      color: 0xf4728a,
      roughness: 0.42,
    });

    const toothMat = new THREE.MeshPhysicalMaterial({
      color: 0xffffff,
      roughness: 0.18,
      clearcoat: 0.8,
    });

    const accentEmissiveMat = new THREE.MeshStandardMaterial({
      color: 0x38bdf8,
      emissive: 0x38bdf8,
      emissiveIntensity: 1.6,
      roughness: 0.2,
    });

    // 2. Lofted High-Poly Orca Body Mesh
    const { geom: bodyGeom, restPositions: bodyRest } = buildOrcaBodyGeometry();
    const bodyMesh = new THREE.Mesh(bodyGeom, bodyMat);
    orcaRoot.add(bodyMesh);

    // Deep narrow inner palate (strictly hidden inside jaw — zero cheek poke-through!)
    const palateGeom = new THREE.SphereGeometry(0.14, 16, 12);
    palateGeom.scale(0.75, 0.22, 1.35);
    const palateMesh = new THREE.Mesh(palateGeom, mouthInnerMat);
    palateMesh.position.set(0, -0.145, 1.12);
    palateMesh.visible = false;
    orcaRoot.add(palateMesh);

    // 3. Articulated 3D Lower Jaw Rig (pivots smoothly down when speaking!)
    const jawPivot = new THREE.Group();
    jawPivot.position.set(0, -0.17, 0.94);
    orcaRoot.add(jawPivot);

    const jawGeom = buildLowerJawGeometry();
    const jawMesh = new THREE.Mesh(jawGeom, whiteJawMat);
    jawPivot.add(jawMesh);

    // 3D Tongue inside lower jaw
    const tongueGeom = new THREE.SphereGeometry(0.13, 16, 12);
    tongueGeom.scale(0.92, 0.28, 1.55);
    const tongueMesh = new THREE.Mesh(tongueGeom, tongueMat);
    tongueMesh.position.set(0, 0.01, 0.25);
    jawPivot.add(tongueMesh);

    // Neat row of cute pearl-white teeth along jaw rim (visible when talking)
    const toothGeom = new THREE.ConeGeometry(0.013, 0.04, 8);
    for (const side of [-1, 1] as const) {
      for (let k = 0; k < 5; k++) {
        const tooth = new THREE.Mesh(toothGeom, toothMat);
        const frac = k / 4;
        const angle = (0.3 + frac * 0.7) * Math.PI * 0.5;
        tooth.position.set(side * Math.sin(angle) * 0.17 * (1 - frac * 0.22), 0.02, 0.48 - frac * 0.30);
        tooth.rotation.z = -side * 0.14;
        jawPivot.add(tooth);
      }
    }

    // 4. Tall Swept Dorsal Fin + Subtle Glowing Cyber Edge
    const dorsalPivot = new THREE.Group();
    dorsalPivot.position.set(0, 0.44, 0.02);
    orcaRoot.add(dorsalPivot);

    const dorsalGeom = buildDorsalFinGeometry();
    const dorsalMesh = new THREE.Mesh(dorsalGeom, finMat);
    dorsalPivot.add(dorsalMesh);

    // Sleek glowing cyber-strip running cleanly along the dorsal trailing arc
    const ledCurve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(0, 0.08, -0.26),
      new THREE.Vector3(0, 0.42, -0.34),
      new THREE.Vector3(0, 0.74, -0.50),
      new THREE.Vector3(0, 0.85, -0.58),
    ]);
    const ledTubeGeom = new THREE.TubeGeometry(ledCurve, 24, 0.013, 8, false);
    const ledTubeMesh = new THREE.Mesh(ledTubeGeom, accentEmissiveMat);
    dorsalPivot.add(ledTubeMesh);

    // 5. Left & Right Paddle-Shaped Pectoral Fins (seated deep into shoulder for 100% seamless joint!)
    const rightFinPivot = new THREE.Group();
    rightFinPivot.position.set(0.32, -0.18, 0.38);
    const rightFinGeom = buildPectoralFinGeometry(1);
    const rightFinMesh = new THREE.Mesh(rightFinGeom, finMat);
    rightFinPivot.add(rightFinMesh);
    orcaRoot.add(rightFinPivot);

    const leftFinPivot = new THREE.Group();
    leftFinPivot.position.set(-0.32, -0.18, 0.38);
    const leftFinGeom = buildPectoralFinGeometry(-1);
    const leftFinMesh = new THREE.Mesh(leftFinGeom, finMat);
    leftFinPivot.add(leftFinMesh);
    orcaRoot.add(leftFinPivot);

    // 6. Twin Crescent Tail Flukes attached at Tail Peduncle End
    const tailPivot = new THREE.Group();
    tailPivot.position.set(0, -0.05, -1.96);
    const rightFlukeGeom = buildTailFlukeLobe(1);
    const leftFlukeGeom = buildTailFlukeLobe(-1);
    const rightFluke = new THREE.Mesh(rightFlukeGeom, finMat);
    const leftFluke = new THREE.Mesh(leftFlukeGeom, finMat);
    tailPivot.add(rightFluke, leftFluke);
    orcaRoot.add(tailPivot);

    // 7. Expressive 3D Glossy Eyes (cursor-tracking pupils + autonomous blinking 3D eyelids + mood brows!)
    const irisMat = new THREE.MeshStandardMaterial({
      color: 0x38bdf8,
      emissive: 0x0284c7,
      emissiveIntensity: 0.75,
      roughness: 0.15,
    });
    const pupilMat = new THREE.MeshBasicMaterial({ color: 0x020617 });
    const glintMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
    const scleraMat = new THREE.MeshPhysicalMaterial({
      color: 0x050912,
      roughness: 0.08,
      clearcoat: 1.0,
      clearcoatRoughness: 0.05,
    });
    const browMat = new THREE.MeshStandardMaterial({
      color: 0xff5a3c,
      emissive: 0xe94a32,
      emissiveIntensity: 0.85,
      roughness: 0.25,
    });

    interface EyeRig {
      group: THREE.Group;
      eyeball: THREE.Group;
      upperLid: THREE.Mesh;
      lowerLid: THREE.Mesh;
      brow: THREE.Mesh;
      side: 1 | -1;
    }

    const eyeRigs: EyeRig[] = [];
    const eyeSample = sampleOrcaSpine(0.155);
    const eyeSphereGeom = new THREE.SphereGeometry(0.072, 22, 18);
    const irisGeom = new THREE.CircleGeometry(0.049, 22);
    const pupilGeom = new THREE.CircleGeometry(0.030, 18);
    const glintBigGeom = new THREE.CircleGeometry(0.015, 12);
    const glintSmallGeom = new THREE.CircleGeometry(0.008, 10);
    const upperLidGeom = new THREE.SphereGeometry(0.078, 20, 14, 0, Math.PI * 2, 0, Math.PI * 0.54);
    const lowerLidGeom = new THREE.SphereGeometry(0.077, 20, 14, 0, Math.PI * 2, Math.PI * 0.46, Math.PI * 0.54);
    const browGeom = new THREE.CapsuleGeometry(0.015, 0.11, 6, 12);

    for (const side of [1, -1] as const) {
      const group = new THREE.Group();
      // Seated flush inside the sleek cheek right in front/below the white post-ocular patch!
      group.position.set(side * (eyeSample.rx * 0.87), eyeSample.spineY - 0.015, eyeSample.z);
      group.rotation.y = side * 1.12;
      group.scale.set(1.0, 0.94, 0.52);

      const eyeball = new THREE.Group();
      const baseSphere = new THREE.Mesh(eyeSphereGeom, scleraMat);
      eyeball.add(baseSphere);

      const iris = new THREE.Mesh(irisGeom, irisMat);
      iris.position.z = 0.071;
      eyeball.add(iris);

      const pupil = new THREE.Mesh(pupilGeom, pupilMat);
      pupil.position.z = 0.073;
      eyeball.add(pupil);

      const glint1 = new THREE.Mesh(glintBigGeom, glintMat);
      glint1.position.set(-0.018, 0.020, 0.075);
      eyeball.add(glint1);

      const glint2 = new THREE.Mesh(glintSmallGeom, glintMat);
      glint2.position.set(0.017, -0.015, 0.075);
      eyeball.add(glint2);

      group.add(eyeball);

      const upperLid = new THREE.Mesh(upperLidGeom, finMat);
      upperLid.rotation.x = -0.95; // open rest
      group.add(upperLid);

      const lowerLid = new THREE.Mesh(lowerLidGeom, finMat);
      lowerLid.rotation.x = 0.95; // open rest
      group.add(lowerLid);

      const brow = new THREE.Mesh(browGeom, browMat);
      brow.position.set(0, 0.098, 0.028);
      brow.rotation.z = Math.PI * 0.5;
      brow.visible = false;
      group.add(brow);

      orcaRoot.add(group);
      eyeRigs.push({ group, eyeball, upperLid, lowerLid, brow, side });
    }

    // 8. Holographic 3D Cyber-Visor (wraps cleanly across brow during scanning / thinking!)
    const visorGeom = new THREE.CylinderGeometry(
      eyeSample.rx * 1.04,
      eyeSample.rx * 1.07,
      0.16,
      32,
      1,
      true,
      -Math.PI * 0.44,
      Math.PI * 0.88
    );
    const visorMat = new THREE.MeshPhysicalMaterial({
      color: 0x38bdf8,
      emissive: 0x0ea5e9,
      emissiveIntensity: 0.8,
      transparent: true,
      opacity: 0.36,
      roughness: 0.08,
      metalness: 0.2,
      side: THREE.DoubleSide,
    });
    const visorMesh = new THREE.Mesh(visorGeom, visorMat);
    visorMesh.position.set(0, eyeSample.spineY + 0.01, eyeSample.z - 0.02);
    visorMesh.visible = false;
    orcaRoot.add(visorMesh);

    // 9. Expanding 3D Echolocation Sonar Rings (emanate forward from melon during scan/talk)
    const sonarRings: { mesh: THREE.Mesh; mat: THREE.MeshBasicMaterial; phase: number }[] = [];
    const sonarGeom = new THREE.TorusGeometry(0.32, 0.011, 10, 40);
    for (let i = 0; i < 3; i++) {
      const mat = new THREE.MeshBasicMaterial({
        color: 0x38bdf8,
        transparent: true,
        opacity: 0,
      });
      const mesh = new THREE.Mesh(sonarGeom, mat);
      mesh.position.set(0, 0.05, 1.75);
      orcaRoot.add(mesh);
      sonarRings.push({ mesh, mat, phase: i / 3 });
    }

    // 10. Floating 3D Hexagonal Guard Shield (upper-right above snout in alert / blocked)
    const shieldGroup = new THREE.Group();
    shieldGroup.position.set(-0.38, 0.90, 1.32);
    const hexRingGeom = new THREE.TorusGeometry(0.24, 0.025, 8, 6);
    const shieldRingMat = new THREE.MeshStandardMaterial({
      color: 0xff5a3c,
      emissive: 0xe94a32,
      emissiveIntensity: 1.5,
      roughness: 0.2,
    });
    const hexRing = new THREE.Mesh(hexRingGeom, shieldRingMat);
    const hexCoreGeom = new THREE.CircleGeometry(0.22, 6);
    const hexCoreMat = new THREE.MeshBasicMaterial({
      color: 0xe94a32,
      transparent: true,
      opacity: 0.2,
      side: THREE.DoubleSide,
    });
    const hexCore = new THREE.Mesh(hexCoreGeom, hexCoreMat);
    const exclBarGeom = new THREE.BoxGeometry(0.048, 0.16, 0.03);
    const exclDotGeom = new THREE.SphereGeometry(0.03, 10, 10);
    const exclMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
    const exclBar = new THREE.Mesh(exclBarGeom, exclMat);
    exclBar.position.y = 0.045;
    const exclDot = new THREE.Mesh(exclDotGeom, exclMat);
    exclDot.position.y = -0.095;
    shieldGroup.add(hexRing, hexCore, exclBar, exclDot);
    shieldGroup.visible = false;
    scene.add(shieldGroup);

    // 11. Ambient Floating Underwater 3D Bubbles
    const bubbleCount = 26;
    const bubbleGeom = new THREE.SphereGeometry(0.034, 12, 10);
    const bubbleMat = new THREE.MeshPhysicalMaterial({
      color: 0xbae6fd,
      roughness: 0.05,
      metalness: 0.05,
      transmission: 0.55,
      transparent: true,
      opacity: 0.45,
      clearcoat: 1.0,
    });
    const bubbles: { mesh: THREE.Mesh; speed: number; baseX: number; baseZ: number; wobble: number; scale: number }[] = [];
    for (let i = 0; i < bubbleCount; i++) {
      const mesh = new THREE.Mesh(bubbleGeom, bubbleMat);
      const scale = 0.4 + Math.random() * 1.15;
      mesh.scale.setScalar(scale);
      const baseX = (Math.random() - 0.5) * 4.2;
      const baseZ = (Math.random() - 0.5) * 4.2;
      mesh.position.set(baseX, (Math.random() - 0.5) * 3.6, baseZ);
      scene.add(mesh);
      bubbles.push({
        mesh,
        speed: 0.28 + Math.random() * 0.42,
        baseX,
        baseZ,
        wobble: Math.random() * Math.PI * 2,
        scale,
      });
    }

    // ResizeObserver for sharp Retina rendering at any panel width (desktop & mobile)
    const handleResize = () => {
      const w = Math.max(container.clientWidth, 64);
      const h = Math.max(container.clientHeight, 64);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h, false);
    };
    handleResize();
    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    // Autonomous blinking clock inside the WebGL loop (zero React re-renders!)
    let nextBlinkAt = 2.2 + Math.random() * 2.4;
    let blinkProgress = 0; // 0 = open, 1 = closed
    let blinkActive = false;

    // Smoothly interpolated animation state
    let simTime = 0;
    let lastTimestamp = performance.now();
    let smoothJaw = 0;
    let smoothLookX = 0.25;
    let smoothLookY = 0;
    let rafId = 0;
    let alive = true;

    const targetRimColor = new THREE.Color(MOOD_COLORS.idle.rim);
    const targetFillColor = new THREE.Color(MOOD_COLORS.idle.fill);
    const targetAccentColor = new THREE.Color(MOOD_COLORS.idle.accent);

    const renderFrame = (now: number) => {
      if (!alive) return;
      rafId = window.requestAnimationFrame(renderFrame);

      const dt = Math.min(0.05, (now - lastTimestamp) / 1000);
      lastTimestamp = now;

      const { mood: curMood, isTalking: talking, mouthLevel: curMouth, paused: isPaused, lookX: lx, lookY: ly } =
        propsRef.current;

      const pal = MOOD_COLORS[curMood];
      targetRimColor.setHex(pal.rim);
      targetFillColor.setHex(pal.fill);
      targetAccentColor.setHex(pal.accent);

      // Smooth lighting & LED color transition
      const lerpRate = isPaused ? 1 : Math.min(1, dt * 5);
      rimLight.color.lerp(targetRimColor, lerpRate);
      bellyBounce.color.lerp(targetFillColor, lerpRate);
      accentEmissiveMat.color.lerp(targetAccentColor, lerpRate);
      accentEmissiveMat.emissive.lerp(targetAccentColor, lerpRate);
      irisMat.color.lerp(targetAccentColor, lerpRate);
      irisMat.emissive.lerp(targetAccentColor, lerpRate);

      const angry = curMood === 'alert' || curMood === 'blocked';
      const scanning = curMood === 'scanning' || curMood === 'thinking';
      const happy = curMood === 'happy';

      if (!isPaused) {
        const swimSpeed = scanning || happy ? 3.5 : talking ? 2.8 : 2.1;
        simTime += dt * swimSpeed;
        pokeEnergyRef.current = Math.max(0, pokeEnergyRef.current - dt * 1.4);

        // Update blink timer
        if (!blinkActive && simTime > nextBlinkAt) {
          blinkActive = true;
          blinkProgress = 0;
        }
        if (blinkActive) {
          blinkProgress += dt * 11.5;
          if (blinkProgress >= Math.PI) {
            blinkActive = false;
            blinkProgress = 0;
            nextBlinkAt = simTime + 3.2 + Math.random() * 5.0;
          }
        }
      }

      const blinkAmt = blinkActive ? Math.sin(blinkProgress) : 0;

      // 1. REALISTIC VERTICAL WHALE SPINE SWIM WAVE (gentle at head, sweeping powerful fluke stroke at tail!)
      const posAttr = bodyGeom.attributes.position as THREE.BufferAttribute;
      const arr = posAttr.array as Float32Array;
      const pokeBoost = 1 + pokeEnergyRef.current * 1.3;
      for (let i = 0; i < arr.length; i += 3) {
        const rx = bodyRest[i];
        const ry = bodyRest[i + 1];
        const rz = bodyRest[i + 2];
        // Normalized 0 at snout (+1.72) -> 1 at tail (-2.02)
        const t = Math.max(0, Math.min(1, (1.72 - rz) / 3.74));
        const amp = Math.pow(t, 1.85) * 0.24 * pokeBoost;
        const dy = Math.sin(simTime - t * 3.1) * amp;
        const dx = Math.sin(simTime * 0.55 - t * 1.8) * Math.pow(t, 1.9) * 0.07;
        arr[i] = rx + dx;
        arr[i + 1] = ry + dy;
        arr[i + 2] = rz;
      }
      posAttr.needsUpdate = true;
      if (!isPaused) {
        bodyGeom.computeVertexNormals();
      }

      // Sync tail flukes cleanly to the oscillating peduncle tip (t = 1.0)
      const tailDy = Math.sin(simTime - 3.1) * 0.24 * pokeBoost;
      const tailDx = Math.sin(simTime * 0.55 - 1.8) * 0.07;
      tailPivot.position.set(tailDx, -0.05 + tailDy, -1.96);
      tailPivot.rotation.x = Math.cos(simTime - 3.1) * 0.42 * pokeBoost;
      tailPivot.rotation.z = Math.sin(simTime * 0.55) * 0.08;

      // Sync dorsal fin subtle elastic flex
      const dorsalWave = Math.sin(simTime - 0.45 * 3.1) * 0.05;
      dorsalPivot.position.y = 0.44 + dorsalWave;
      dorsalPivot.rotation.z = Math.sin(simTime * 0.65) * 0.05;

      // 2. Pectoral fins graceful 3D paddling (+ enthusiastic wave when talking / happy / poked!)
      const finAmp = talking || happy ? 0.28 : 0.14;
      const finWave = Math.sin(simTime * (talking ? 1.45 : 0.9)) * finAmp;
      rightFinPivot.rotation.z = -0.22 + finWave + pokeEnergyRef.current * 0.45;
      rightFinPivot.rotation.x = 0.10 + Math.cos(simTime * 0.9) * 0.12;
      leftFinPivot.rotation.z = 0.22 - finWave * 0.85 - pokeEnergyRef.current * 0.45;
      leftFinPivot.rotation.x = 0.10 - Math.cos(simTime * 0.9) * 0.12;

      // 3. Smooth Cursor Tracking + Gentle Buoyant Floating + Barrel Roll on Click!
      smoothLookX += ((isPaused ? 0.2 : lx) - smoothLookX) * (isPaused ? 1 : Math.min(1, dt * 6));
      smoothLookY += ((isPaused ? 0 : ly) - smoothLookY) * (isPaused ? 1 : Math.min(1, dt * 6));

      const hoverY = Math.sin(simTime * 0.7) * 0.07 + (happy ? Math.abs(Math.sin(simTime * 1.2)) * 0.09 : 0);
      const pokeHop = Math.sin(pokeEnergyRef.current * Math.PI) * 0.22;
      orcaRoot.position.y = hoverY + pokeHop;

      const pokeSpin = Math.sin(pokeEnergyRef.current * Math.PI) * 0.42;
      orcaRoot.rotation.y = -0.06 + smoothLookX * 0.24 - pokeSpin;
      orcaRoot.rotation.x = smoothLookY * 0.14 + Math.sin(simTime * 0.65) * 0.04;
      orcaRoot.rotation.z = smoothLookX * 0.07 + Math.cos(simTime * 0.65) * 0.04 - pokeSpin * 0.42;

      // 4. REAL 3D ARTICULATED LOWER JAW LIP-SYNC!
      const targetJawAngle = talking && !isPaused ? [0.02, 0.16, 0.30, 0.44][Math.min(3, Math.max(0, curMouth))] : happy ? 0.08 : 0.0;
      smoothJaw += (targetJawAngle - smoothJaw) * (isPaused ? 1 : Math.min(1, dt * 20));
      jawPivot.rotation.x = smoothJaw;
      palateMesh.visible = smoothJaw > 0.05;

      // 5. Eyes tracking + Blinking + Mood Expressions (fierce angled brows, joyful ^ ^ squint)
      for (const eye of eyeRigs) {
        eye.eyeball.rotation.y = smoothLookX * 0.28 * eye.side;
        eye.eyeball.rotation.x = smoothLookY * 0.24;

        // Upper lid: drops down on blink OR angles fiercely in alert/blocked
        const angryLid = angry ? 0.36 : 0;
        eye.upperLid.rotation.x = -0.95 + blinkAmt * 0.98 + angryLid;
        eye.upperLid.rotation.z = angry ? -0.35 * eye.side : 0;

        // Lower lid: pushes up into happy crescent smile in happy mood OR closes on blink
        const happySquint = happy ? 0.68 : 0;
        eye.lowerLid.rotation.x = 0.95 - blinkAmt * 0.85 - happySquint;

        // Visible glowing angled 3D eyebrows in alert/blocked
        eye.brow.visible = angry;
        if (angry) {
          eye.brow.rotation.z = Math.PI * 0.5 - 0.34 * eye.side;
        }
      }

      // 6. Holographic 3D Visor on Scanning / Thinking
      visorMesh.visible = scanning;
      if (scanning) {
        visorMat.color.copy(targetAccentColor);
        visorMat.emissive.copy(targetAccentColor);
        visorMat.opacity = 0.26 + 0.12 * Math.sin(simTime * 3.0);
      }

      // 7. 3D Echolocation Sonar Rings (active during scanning, thinking, or talking!)
      const showSonar = (scanning || talking) && !isPaused;
      for (const ring of sonarRings) {
        if (!showSonar) {
          ring.mat.opacity = 0;
          continue;
        }
        ring.phase = (ring.phase + dt * (scanning ? 0.85 : 0.65)) % 1;
        const p = ring.phase;
        ring.mesh.position.z = 1.65 + p * 1.15;
        ring.mesh.scale.setScalar(0.35 + p * 1.45);
        ring.mat.color.copy(targetAccentColor);
        ring.mat.opacity = Math.sin(p * Math.PI) * (scanning ? 0.72 : 0.42);
      }

      // 8. Floating 3D Hexagonal Crimson Shield in Alert / Blocked (oriented toward camera)
      shieldGroup.visible = angry;
      if (angry) {
        shieldGroup.position.y = 0.92 + Math.sin(simTime * 1.4) * 0.08;
        shieldGroup.lookAt(camera.position);
        shieldGroup.rotateY(Math.sin(simTime * 0.9) * 0.24);
      }

      // 9. Rising Ambient 3D Underwater Bubbles
      for (const b of bubbles) {
        if (!isPaused) {
          b.mesh.position.y += dt * b.speed * (1 + pokeEnergyRef.current * 2.2);
          b.mesh.position.x = b.baseX + Math.sin(simTime * 0.8 + b.wobble) * 0.14;
          if (b.mesh.position.y > 2.1) {
            b.mesh.position.y = -2.0;
          }
        }
      }

      renderer.render(scene, camera);
    };

    rafId = window.requestAnimationFrame(renderFrame);

    return () => {
      alive = false;
      window.cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      skinTex.dispose();
      bodyGeom.dispose();
      palateGeom.dispose();
      jawGeom.dispose();
      tongueGeom.dispose();
      toothGeom.dispose();
      dorsalGeom.dispose();
      ledTubeGeom.dispose();
      rightFinGeom.dispose();
      leftFinGeom.dispose();
      rightFlukeGeom.dispose();
      leftFlukeGeom.dispose();
      eyeSphereGeom.dispose();
      irisGeom.dispose();
      pupilGeom.dispose();
      glintBigGeom.dispose();
      glintSmallGeom.dispose();
      upperLidGeom.dispose();
      lowerLidGeom.dispose();
      browGeom.dispose();
      visorGeom.dispose();
      sonarGeom.dispose();
      hexRingGeom.dispose();
      hexCoreGeom.dispose();
      exclBarGeom.dispose();
      exclDotGeom.dispose();
      bubbleGeom.dispose();
      bodyMat.dispose();
      finMat.dispose();
      whiteJawMat.dispose();
      mouthInnerMat.dispose();
      tongueMat.dispose();
      toothMat.dispose();
      accentEmissiveMat.dispose();
      irisMat.dispose();
      pupilMat.dispose();
      glintMat.dispose();
      scleraMat.dispose();
      browMat.dispose();
      visorMat.dispose();
      shieldRingMat.dispose();
      hexCoreMat.dispose();
      exclMat.dispose();
      bubbleMat.dispose();
      sonarRings.forEach((r) => r.mat.dispose());
      renderer.dispose();
      if (renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  const pal = MOOD_COLORS[mood];

  if (webglFailed) {
    return (
      <div
        className={cn(
          'w-full h-full flex items-center justify-center font-mono text-xs text-sky-400',
          className
        )}
        style={{ background: `radial-gradient(circle at 50% 45%, ${pal.bgTop}, ${pal.bgBottom})` }}
      >
        aegis.orca 3D
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label="Aegis Orca — живая 3D косатка-помощник"
      className={cn('w-full h-full select-none', className)}
      style={{
        background: `radial-gradient(circle at 52% 44%, ${pal.bgTop} 0%, ${pal.bgBottom} 82%)`,
      }}
    />
  );
}
