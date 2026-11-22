'use client';

import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrcaMood } from '@/components/OrcaRigSvg';
import { cn } from '@/lib/utils';

interface OrcaLive2DCanvasProps {
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

type FrameKey = 'idle' | 'talk_mid' | 'talk_wide' | 'blink' | 'happy' | 'alert';

const FRAME_URLS: Record<FrameKey, string> = {
  idle: '/orca/idle.webp',
  talk_mid: '/orca/talk_mid.webp',
  talk_wide: '/orca/talk_wide.webp',
  blink: '/orca/blink.webp',
  happy: '/orca/happy.webp',
  alert: '/orca/alert.webp',
};

const MOOD_TINT: Record<OrcaMood, { rgb: [number, number, number]; strength: number }> = {
  idle: { rgb: [0.22, 0.74, 0.97], strength: 0.14 },
  thinking: { rgb: [0.96, 0.62, 0.04], strength: 0.24 },
  scanning: { rgb: [0.13, 0.83, 0.93], strength: 0.28 },
  alert: { rgb: [0.95, 0.29, 0.20], strength: 0.32 },
  blocked: { rgb: [0.91, 0.29, 0.20], strength: 0.30 },
  happy: { rgb: [0.25, 0.75, 0.50], strength: 0.24 },
};

const VERTEX_SHADER = /* glsl */ `
  uniform float uTime;
  uniform vec2 uLook;
  uniform float uTalk;
  uniform float uPoke;
  uniform float uSpeed;
  varying vec2 vUv;

  void main() {
    vUv = uv;
    vec3 pos = position;

    // 1. Live2D organic tail swim wave (smoothly weighted toward left-bottom tail fluke, zero face distortion)
    float tailMask = smoothstep(0.46, 0.08, uv.x) * smoothstep(0.70, 0.15, uv.y);
    float tailWaveY = sin(uTime * 2.2 * uSpeed - uv.x * 5.4) * 0.052 * (1.0 + uPoke * 1.4);
    float tailWaveX = cos(uTime * 1.9 * uSpeed - uv.x * 4.0) * 0.018;
    pos.y += tailWaveY * tailMask;
    pos.x += tailWaveX * tailMask;

    // 2. Pectoral fins gentle 3D underwater paddle (bottom-center & bottom-right fins)
    float finMask = smoothstep(0.46, 0.14, uv.y) * smoothstep(0.28, 0.48, uv.x);
    float finPaddle = sin(uTime * 2.0 * uSpeed + uv.x * 3.8) * (0.022 + uTalk * 0.014 + uPoke * 0.032);
    pos.y += finPaddle * finMask;
    pos.x += cos(uTime * 2.0 * uSpeed + uv.x * 3.8) * 0.012 * finMask;

    // 3. Tall dorsal fin elastic sway (top-center)
    float dorsalMask = smoothstep(0.62, 0.92, uv.y) * smoothstep(0.25, 0.44, uv.x) * smoothstep(0.68, 0.48, uv.x);
    pos.x += sin(uTime * 1.8 * uSpeed - 0.8) * 0.022 * dorsalMask;

    // 4. Subtle chest breathing & buoyant float
    float centerDist = length(uv - vec2(0.55, 0.48));
    float breathMask = smoothstep(0.42, 0.05, centerDist);
    float breath = sin(uTime * 1.45) * 0.014;
    pos.xy += (uv - vec2(0.55, 0.48)) * breath * breathMask;
    pos.y += sin(uTime * 1.25) * 0.022 + sin(uPoke * 3.14159) * 0.065;

    // 5. 2.5D head parallax shift toward cursor (makes the face feel genuinely sculpted in depth)
    float headMask = smoothstep(0.42, 0.78, uv.x) * smoothstep(0.25, 0.65, uv.y);
    pos.x += uLook.x * 0.024 * headMask;
    pos.y += -uLook.y * 0.018 * headMask;
    pos.z += headMask * 0.06 + uTalk * 0.018 * headMask;

    gl_Position = projectionMatrix * modelViewMatrix * vec4(pos, 1.0);
  }
`;

const FRAGMENT_SHADER = /* glsl */ `
  uniform sampler2D uTexA;
  uniform sampler2D uTexB;
  uniform float uBlend;
  uniform float uTime;
  uniform vec3 uMoodColor;
  uniform float uMoodStrength;
  uniform float uScanActive;
  uniform float uTalkActive;
  uniform float uPoke;
  varying vec2 vUv;

  void main() {
    vec4 colA = texture2D(uTexA, vUv);
    vec4 colB = texture2D(uTexB, vUv);
    vec3 col = mix(colA.rgb, colB.rgb, uBlend);

    // Subtle underwater top-down caustic shimmer (cinematic deep-sea light rays)
    float ray1 = sin(vUv.x * 11.0 + vUv.y * 4.5 - uTime * 0.9) * 0.5 + 0.5;
    float ray2 = sin(vUv.x * 17.0 - vUv.y * 6.0 + uTime * 0.65) * 0.5 + 0.5;
    float caustic = pow(ray1 * ray2, 2.4) * smoothstep(0.32, 0.98, vUv.y);
    col += uMoodColor * caustic * (0.09 + uScanActive * 0.08);

    // Mood atmospheric rim/vignette glow around perimeter (keeps subject skin crisp & natural)
    float edgeDist = length((vUv - vec2(0.52, 0.48)) * vec2(1.05, 1.05));
    float rimGlow = smoothstep(0.36, 0.78, edgeDist);
    col += uMoodColor * rimGlow * uMoodStrength * 0.38;

    // Expanding echolocation sonar rings emanating from melon forehead (uv ~ 0.76, 0.56) during scan / talk / poke
    float sonarVis = max(uScanActive * 0.85, max(uTalkActive * 0.30, uPoke * 0.75));
    if (sonarVis > 0.01) {
      float d = length((vUv - vec2(0.78, 0.54)) * vec2(1.0, 1.0));
      float wave1 = fract(uTime * 0.52);
      float wave2 = fract(uTime * 0.52 + 0.5);
      float ring1 = exp(-pow((d - wave1 * 0.62) / 0.012, 2.0)) * (1.0 - wave1);
      float ring2 = exp(-pow((d - wave2 * 0.62) / 0.012, 2.0)) * (1.0 - wave2);
      // Forward cone bias toward right side of frame
      float cone = smoothstep(0.52, 0.84, vUv.x);
      col += uMoodColor * (ring1 + ring2) * sonarVis * (0.45 + 0.55 * cone);
    }

    // Subtle horizontal HUD scan sweep during active code scanning
    if (uScanActive > 0.01) {
      float sweepY = 1.0 - fract(uTime * 0.42);
      float sweepLine = exp(-pow((vUv.y - sweepY) / 0.018, 2.0));
      col += uMoodColor * sweepLine * 0.24 * uScanActive;
    }

    gl_FragColor = vec4(col, 1.0);
  }
`;

export function OrcaLive2DCanvas({
  mood,
  isTalking,
  mouthLevel,
  paused = false,
  lookX = 0,
  lookY = 0,
  pokeTrigger = 0,
  className,
}: OrcaLive2DCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [fallbackMode, setFallbackMode] = useState(false);

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
      queueMicrotask(() => setFallbackMode(true));
      return;
    }

    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    renderer.domElement.style.display = 'block';
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 20);
    camera.position.set(0, 0, 3.18);

    // Preload all 6 pixel-aligned studio expression/viseme textures
    const loader = new THREE.TextureLoader();
    const textures = {} as Record<FrameKey, THREE.Texture>;
    const frameKeys: FrameKey[] = ['idle', 'talk_mid', 'talk_wide', 'blink', 'happy', 'alert'];
    for (const key of frameKeys) {
      const tex = loader.load(FRAME_URLS[key]);
      tex.colorSpace = THREE.SRGBColorSpace;
      tex.minFilter = THREE.LinearFilter;
      tex.magFilter = THREE.LinearFilter;
      tex.generateMipmaps = false;
      textures[key] = tex;
    }

    // 48x48 Live2D deformable mesh plane
    const planeGeom = new THREE.PlaneGeometry(2.14, 2.14, 48, 48);
    const shaderMat = new THREE.ShaderMaterial({
      vertexShader: VERTEX_SHADER,
      fragmentShader: FRAGMENT_SHADER,
      uniforms: {
        uTexA: { value: textures.idle },
        uTexB: { value: textures.idle },
        uBlend: { value: 0 },
        uTime: { value: 0 },
        uLook: { value: new THREE.Vector2(0, 0) },
        uTalk: { value: 0 },
        uPoke: { value: 0 },
        uSpeed: { value: 1 },
        uMoodColor: { value: new THREE.Vector3(0.22, 0.74, 0.97) },
        uMoodStrength: { value: 0.14 },
        uScanActive: { value: 0 },
        uTalkActive: { value: 0 },
      },
    });
    const orcaPlane = new THREE.Mesh(planeGeom, shaderMat);
    scene.add(orcaPlane);

    // Subtle rising translucent underwater bubbles (3D depth particles in front of plane)
    const bubbleCount = 18;
    const bubbleGeom = new THREE.RingGeometry(0.012, 0.022, 16);
    const bubbleMat = new THREE.MeshBasicMaterial({
      color: 0xbbe8ff,
      transparent: true,
      opacity: 0.34,
      side: THREE.DoubleSide,
    });
    const bubbles: { mesh: THREE.Mesh; baseX: number; speed: number; wobble: number }[] = [];
    for (let i = 0; i < bubbleCount; i++) {
      const mesh = new THREE.Mesh(bubbleGeom, bubbleMat);
      const scale = 0.55 + Math.random() * 1.15;
      mesh.scale.setScalar(scale);
      const baseX = (Math.random() - 0.5) * 1.85;
      mesh.position.set(baseX, (Math.random() - 0.5) * 2.0, 0.18 + Math.random() * 0.12);
      scene.add(mesh);
      bubbles.push({
        mesh,
        baseX,
        speed: 0.16 + Math.random() * 0.22,
        wobble: Math.random() * Math.PI * 2,
      });
    }

    // Crisp ResizeObserver keeping exact square cover aspect without stretching the character
    const handleResize = () => {
      const w = Math.max(container.clientWidth, 64);
      const h = Math.max(container.clientHeight, 64);
      const aspect = w / h;
      camera.aspect = aspect;
      // Cover-fit: scale camera distance so 1:1 artwork always fills nicely with zero cropping of nose/tail
      camera.position.z = aspect >= 1 ? 3.16 / Math.min(aspect, 1.14) : 3.16;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h, false);
    };
    handleResize();
    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    // Smooth crossfade state machine between expression/viseme frames
    let currentKey: FrameKey = 'idle';
    let targetKey: FrameKey = 'idle';
    let blend = 1.0;

    // Autonomous natural blink scheduler
    let simTime = 0;
    let nextBlinkAt = 2.4 + Math.random() * 2.4;
    let blinkRemaining = 0;

    let smoothLookX = 0;
    let smoothLookY = 0;
    let smoothTalk = 0;
    let smoothScan = 0;
    let lastTs = performance.now();
    let rafId = 0;
    let alive = true;

    const currentMoodRgb = new THREE.Vector3(0.22, 0.74, 0.97);
    const desiredMoodRgb = new THREE.Vector3(0.22, 0.74, 0.97);

    const tick = (now: number) => {
      if (!alive) return;
      rafId = window.requestAnimationFrame(tick);

      const dt = Math.min(0.05, (now - lastTs) / 1000);
      lastTs = now;

      const { mood: curMood, isTalking: talking, mouthLevel: curMouth, paused: isPaused, lookX: lx, lookY: ly } =
        propsRef.current;

      const tint = MOOD_TINT[curMood];
      desiredMoodRgb.set(tint.rgb[0], tint.rgb[1], tint.rgb[2]);
      const lerpFactor = isPaused ? 1 : Math.min(1, dt * 6);
      currentMoodRgb.lerp(desiredMoodRgb, lerpFactor);

      const isScanningMood = curMood === 'scanning' || curMood === 'thinking';
      const isAlertMood = curMood === 'alert' || curMood === 'blocked';
      const isHappyMood = curMood === 'happy';

      if (!isPaused) {
        const speedMul = isScanningMood || isHappyMood ? 1.35 : talking ? 1.18 : 1.0;
        simTime += dt;
        shaderMat.uniforms.uSpeed.value = speedMul;
        pokeEnergyRef.current = Math.max(0, pokeEnergyRef.current - dt * 1.45);

        // Trigger autonomous natural blink every 2.8–5.6s
        if (blinkRemaining <= 0 && simTime >= nextBlinkAt) {
          blinkRemaining = 0.14;
          nextBlinkAt = simTime + 2.8 + Math.random() * 2.8;
        }
        if (blinkRemaining > 0) {
          blinkRemaining = Math.max(0, blinkRemaining - dt);
        }
      }

      // Determine target frame priority: talking lip-sync > blink > mood expression > idle
      let nextKey: FrameKey = 'idle';
      if (talking && !isPaused && curMouth >= 2) {
        nextKey = curMouth >= 3 ? 'talk_wide' : 'talk_mid';
      } else if (talking && !isPaused && curMouth === 1) {
        nextKey = 'talk_mid';
      } else if (blinkRemaining > 0 && !isHappyMood && !isPaused) {
        nextKey = 'blink';
      } else if (isAlertMood) {
        nextKey = 'alert';
      } else if (isHappyMood) {
        nextKey = 'happy';
      } else {
        nextKey = 'idle';
      }

      if (nextKey !== targetKey) {
        // Snap source texture to latest dominant frame before starting crisp crossfade
        currentKey = blend > 0.5 ? targetKey : currentKey;
        targetKey = nextKey;
        blend = 0;
        shaderMat.uniforms.uTexA.value = textures[currentKey];
        shaderMat.uniforms.uTexB.value = textures[targetKey];
      }

      // Snappy crossfade for lip-sync & blinks (~45ms), silky smooth for mood switches (~160ms)
      const fadeSpeed = talking || targetKey === 'blink' || currentKey === 'blink' ? 22.0 : 6.5;
      blend = isPaused ? 1 : Math.min(1, blend + dt * fadeSpeed);

      smoothLookX += ((isPaused ? 0 : lx) - smoothLookX) * (isPaused ? 1 : Math.min(1, dt * 6));
      smoothLookY += ((isPaused ? 0 : ly) - smoothLookY) * (isPaused ? 1 : Math.min(1, dt * 6));
      smoothTalk += ((talking && !isPaused ? 1 : 0) - smoothTalk) * (isPaused ? 1 : Math.min(1, dt * 10));
      smoothScan += ((isScanningMood ? 1 : 0) - smoothScan) * (isPaused ? 1 : Math.min(1, dt * 5));

      // Gentle 2.5D card tilt following cursor + playful roll on poke
      const pokeTilt = Math.sin(pokeEnergyRef.current * Math.PI) * 0.14;
      orcaPlane.rotation.y = smoothLookX * 0.13 + pokeTilt;
      orcaPlane.rotation.x = smoothLookY * 0.09;
      orcaPlane.rotation.z = -smoothLookX * 0.025 + pokeTilt * 0.35;

      // Update GLSL shader uniforms
      shaderMat.uniforms.uBlend.value = blend;
      shaderMat.uniforms.uTime.value = simTime;
      shaderMat.uniforms.uLook.value.set(smoothLookX, smoothLookY);
      shaderMat.uniforms.uTalk.value = smoothTalk;
      shaderMat.uniforms.uPoke.value = pokeEnergyRef.current;
      shaderMat.uniforms.uMoodColor.value.copy(currentMoodRgb);
      shaderMat.uniforms.uMoodStrength.value = tint.strength;
      shaderMat.uniforms.uScanActive.value = smoothScan;
      shaderMat.uniforms.uTalkActive.value = smoothTalk;

      // Animate floating underwater bubbles
      for (const b of bubbles) {
        if (!isPaused) {
          b.mesh.position.y += dt * b.speed * (1 + pokeEnergyRef.current * 2.5);
          b.mesh.position.x = b.baseX + Math.sin(simTime * 1.1 + b.wobble) * 0.06;
          if (b.mesh.position.y > 1.15) {
            b.mesh.position.y = -1.15;
          }
        }
      }

      renderer.render(scene, camera);
    };

    rafId = window.requestAnimationFrame(tick);

    return () => {
      alive = false;
      window.cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      planeGeom.dispose();
      shaderMat.dispose();
      bubbleGeom.dispose();
      bubbleMat.dispose();
      for (const key of frameKeys) {
        textures[key].dispose();
      }
      renderer.dispose();
      if (renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  if (fallbackMode) {
    const src =
      isTalking && mouthLevel >= 3
        ? FRAME_URLS.talk_wide
        : isTalking && mouthLevel >= 1
        ? FRAME_URLS.talk_mid
        : mood === 'alert' || mood === 'blocked'
        ? FRAME_URLS.alert
        : mood === 'happy'
        ? FRAME_URLS.happy
        : FRAME_URLS.idle;
    return (
      /* eslint-disable-next-line @next/next/no-img-element */
      <img
        src={src}
        alt="Aegis Orca — живая косатка-помощник"
        className={cn('w-full h-full object-cover select-none', className)}
        draggable={false}
      />
    );
  }

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label="Aegis Orca — анимированная говорящая косатка-помощник"
      className={cn('w-full h-full select-none bg-[#06111d]', className)}
    />
  );
}
