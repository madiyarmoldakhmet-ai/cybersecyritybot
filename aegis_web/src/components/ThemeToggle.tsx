'use client';

import { useTheme } from 'next-themes';
import { Moon, Sun } from 'lucide-react';
import { useEffect, useSyncExternalStore } from 'react';

const emptySubscribe = () => () => {};

function syncColorSchemeMeta(mode: string | undefined) {
  if (typeof document === 'undefined') return;
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (!meta) return;
  if (mode === 'dark' || mode === 'light') {
    meta.setAttribute('content', mode);
  } else {
    meta.setAttribute('content', 'light dark');
  }
}

export function ThemeToggle() {
  const { theme, resolvedTheme, setTheme } = useTheme();
  const mounted = useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false
  );

  useEffect(() => {
    if (!mounted) return;
    syncColorSchemeMeta(theme === 'system' ? undefined : theme);
  }, [mounted, theme]);

  if (!mounted) {
    return <div className="min-h-8 min-w-8 border-2 border-[var(--color-line)]" />;
  }

  const currentRendered = resolvedTheme === 'dark' ? 'dark' : 'light';
  const handleToggle = () => {
    const target = currentRendered === 'dark' ? 'light' : 'dark';
    const systemDark =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-color-scheme: dark)').matches;
    const systemPref = systemDark ? 'dark' : 'light';

    if (target === systemPref) {
      setTheme('system');
      syncColorSchemeMeta(undefined);
    } else {
      setTheme(target);
      syncColorSchemeMeta(target);
    }
  };

  return (
    <button
      type="button"
      onClick={handleToggle}
      className="pixel-btn min-h-8 min-w-8 bg-[var(--color-panel)] text-[var(--color-moon)] inline-flex items-center justify-center cursor-pointer"
      aria-label={currentRendered === 'dark' ? 'Включить светлую пиксельную тему' : 'Включить ночную пиксельную тему'}
    >
      {currentRendered === 'dark' ? (
        <Sun className="w-3.5 h-3.5" aria-hidden="true" />
      ) : (
        <Moon className="w-3.5 h-3.5 text-[var(--color-ink)]" aria-hidden="true" />
      )}
    </button>
  );
}
