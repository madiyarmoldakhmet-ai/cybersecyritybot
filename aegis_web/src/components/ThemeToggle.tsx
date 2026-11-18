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
    return <div className="min-h-9 min-w-9 rounded-full border border-[var(--color-line)]" />;
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
      className="min-h-9 min-w-9 rounded-full border border-[var(--color-line)] hover:border-[var(--color-line-strong)] bg-[var(--color-panel)] text-[var(--color-ink)] transition-colors inline-flex items-center justify-center cursor-pointer"
      aria-label={currentRendered === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему'}
    >
      {currentRendered === 'dark' ? (
        <Sun className="w-4 h-4" aria-hidden="true" />
      ) : (
        <Moon className="w-4 h-4" aria-hidden="true" />
      )}
    </button>
  );
}
