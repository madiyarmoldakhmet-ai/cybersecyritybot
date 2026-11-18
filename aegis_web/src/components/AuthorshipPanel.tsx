'use client';

import { useState } from 'react';
import { Check, Copy, KeyRound, Lock, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface AuthorshipState {
  verified: boolean;
  target: string;
  targetType: 'github' | 'domain';
  method: string;
  actor: string;
  role: string;
  canCreatePr: boolean;
  message: string;
  proofToken: string;
  githubToken: string;
}

interface AuthorshipPanelProps {
  targetInput: string;
  onTargetInputChange: (val: string) => void;
  authorship: AuthorshipState;
  onAuthorshipChange: (next: AuthorshipState) => void;
  requireOwnership: boolean;
  onRequireOwnershipChange: (checked: boolean) => void;
  onAskAi?: (prompt: string) => void;
}

type VerifyMethod = 'challenge' | 'token' | 'dns_txt';

export function AuthorshipPanel({
  targetInput,
  onTargetInputChange,
  authorship,
  onAuthorshipChange,
  requireOwnership,
  onRequireOwnershipChange,
  onAskAi,
}: AuthorshipPanelProps) {
  const [method, setMethod] = useState<VerifyMethod>('challenge');
  const [tokenInput, setTokenInput] = useState(authorship.githubToken || '');
  const [challengeCode, setChallengeCode] = useState('');
  const [instructions, setInstructions] = useState<string[]>([]);
  const [loadingChallenge, setLoadingChallenge] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [copied, setCopied] = useState(false);

  const handleIssueChallenge = async () => {
    const cleanTarget = targetInput.trim();
    if (!cleanTarget) {
      setErrorMsg('Укажите URL или owner/repo / домен.');
      return;
    }
    setErrorMsg('');
    setLoadingChallenge(true);
    try {
      const targetType = method === 'dns_txt' ? 'domain' : 'github';
      const res = await fetch('/api/v1/verify/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: cleanTarget, target_type: targetType }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.detail || 'Не удалось сгенерировать код подтверждения.');
        return;
      }
      setChallengeCode(data.challenge_code || '');
      setInstructions(Array.isArray(data.instructions) ? data.instructions : []);
    } catch (err) {
      setErrorMsg(`Ошибка сети: ${err}`);
    } finally {
      setLoadingChallenge(false);
    }
  };

  const handleVerify = async () => {
    const cleanTarget = targetInput.trim();
    if (!cleanTarget) {
      setErrorMsg('Сначала укажите репозиторий или домен.');
      return;
    }
    if (method === 'token' && !tokenInput.trim()) {
      setErrorMsg('Вставьте GitHub Personal Access Token (или выберите Commit Challenge без токена).');
      return;
    }
    if (method !== 'token' && !challengeCode.trim()) {
      setErrorMsg('Сначала нажмите «Получить код», добавьте его в репо/DNS и затем проверьте.');
      return;
    }

    setErrorMsg('');
    setVerifying(true);
    try {
      const res = await fetch('/api/v1/verify/ownership', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: cleanTarget,
          method,
          github_token: method === 'token' ? tokenInput.trim() : undefined,
          challenge_code: method !== 'token' ? challengeCode.trim() : undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.detail || 'Ошибка проверки авторства.');
        return;
      }
      onAuthorshipChange({
        verified: Boolean(data.verified),
        target: data.target || cleanTarget,
        targetType: data.target_type === 'domain' ? 'domain' : 'github',
        method: data.method || method,
        actor: data.username || data.repo_owner || '',
        role: data.role || 'None',
        canCreatePr: Boolean(data.can_create_pr),
        message: data.message || '',
        proofToken: data.proof_token || '',
        githubToken: method === 'token' ? tokenInput.trim() : authorship.githubToken,
      });
      if (!data.verified && data.message) {
        setErrorMsg(data.message);
      }
    } catch (err) {
      setErrorMsg(`Ошибка сети: ${err}`);
    } finally {
      setVerifying(false);
    }
  };

  const handleCopyCode = async () => {
    if (!challengeCode) return;
    try {
      await navigator.clipboard.writeText(challengeCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[11px] uppercase tracking-wider text-[var(--color-muted-soft)]">
          ПОДТВЕРЖДЕНИЕ АВТОРСТВА
        </span>
        <span
          className={cn(
            'font-mono text-[11px] px-2 py-0.5 rounded border',
            authorship.verified
              ? 'border-[#3fbf7f]/40 text-[#3fbf7f] bg-[#3fbf7f]/10'
              : 'border-[var(--color-line)] text-[var(--color-muted-soft)] bg-[var(--color-raised)]'
          )}
        >
          {authorship.verified ? `VERIFIED · ${authorship.role}` : 'UNVERIFIED'}
        </span>
      </div>

      {/* Method switcher pills */}
      <div className="grid grid-cols-3 gap-1.5" role="group" aria-label="Способ подтверждения авторства">
        {(
          [
            { id: 'challenge', label: 'Commit / File' },
            { id: 'token', label: 'GitHub Token' },
            { id: 'dns_txt', label: 'DNS TXT' },
          ] as const
        ).map((item) => (
          <button
            key={item.id}
            type="button"
            aria-pressed={method === item.id}
            onClick={() => {
              setMethod(item.id);
              setErrorMsg('');
            }}
            className={cn(
              'min-h-8 px-2 py-1 rounded-lg border font-mono text-[11px] transition-colors cursor-pointer truncate',
              method === item.id
                ? 'border-[#e94a32] bg-[var(--color-panel)] text-[var(--color-ink)]'
                : 'border-[var(--color-line)] bg-[var(--color-paper)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
            )}
          >
            {item.label}
          </button>
        ))}
      </div>

      {/* Target input */}
      <div className="space-y-1.5">
        <label htmlFor="cg-verify-target" className="block font-mono text-[11px] text-[var(--color-muted-soft)]">
          {method === 'dns_txt' ? 'Домен для DAST-аудита' : 'GitHub репозиторий (URL или owner/repo)'}
        </label>
        <input
          id="cg-verify-target"
          type="text"
          value={targetInput}
          onChange={(e) => onTargetInputChange(e.target.value)}
          placeholder={method === 'dns_txt' ? 'app.fintech.kz' : 'https://github.com/owner/repo'}
          className="w-full min-h-9 px-3 py-1.5 rounded-lg bg-[var(--color-paper)] border border-[var(--color-line)] focus:border-[#e94a32] text-sm font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
        />
      </div>

      {method === 'token' ? (
        <div className="space-y-2">
          <label htmlFor="cg-gh-token" className="block font-mono text-[11px] text-[var(--color-muted-soft)]">
            Personal Access Token (не сохраняется на сервере)
          </label>
          <input
            id="cg-gh-token"
            type="password"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="Token c правами repo (Owner / Write)"
            className="w-full min-h-9 px-3 py-1.5 rounded-lg bg-[var(--color-paper)] border border-[var(--color-line)] focus:border-[#e94a32] text-sm font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
          />
          <button
            type="button"
            disabled={verifying}
            onClick={handleVerify}
            className="w-full min-h-9 px-3.5 py-2 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-xs uppercase tracking-wider inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
          >
            <KeyRound className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{verifying ? 'Проверяю права...' : 'Проверить авторство по Token'}</span>
          </button>
        </div>
      ) : (
        <div className="space-y-2.5">
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={loadingChallenge}
              onClick={handleIssueChallenge}
              className="flex-1 min-h-9 px-3 py-1.5 rounded-full border border-[var(--color-line-strong)] bg-[var(--color-raised)] hover:border-[var(--color-ink)] font-mono text-xs text-[var(--color-ink)] transition-colors cursor-pointer"
            >
              {loadingChallenge ? 'Генерирую...' : challengeCode ? 'Обновить код' : '1. Получить код'}
            </button>
            <button
              type="button"
              disabled={verifying || !challengeCode}
              onClick={handleVerify}
              className="flex-1 min-h-9 px-3 py-1.5 rounded-full bg-[var(--color-ink)] hover:bg-[#e94a32] text-[var(--color-canvas)] hover:text-white font-mono text-xs transition-colors cursor-pointer disabled:opacity-45"
            >
              {verifying ? 'Проверка...' : '2. Проверить сейчас'}
            </button>
          </div>

          {challengeCode && (
            <div className="rounded-lg border border-[var(--color-line)] bg-[var(--color-paper)] p-3 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <code className="font-mono text-xs text-[#e94a32] break-all">{challengeCode}</code>
                <button
                  type="button"
                  onClick={handleCopyCode}
                  aria-label="Скопировать код подтверждения"
                  className="min-h-7 px-2 py-0.5 rounded border border-[var(--color-line)] hover:border-[var(--color-line-strong)] font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]"
                >
                  {copied ? <Check className="w-3 h-3 text-[#3fbf7f]" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Скопировано' : 'Копия'}</span>
                </button>
              </div>
              {instructions.length > 0 && (
                <ul className="space-y-1 font-mono text-[11px] text-[var(--color-muted-soft)] leading-relaxed">
                  {instructions.map((line, i) => (
                    <li key={i} className="break-words">{line}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {/* Structured Inspection Rows echoing prtner.ai card */}
      <div className="rounded-lg border border-[var(--color-line)] bg-[var(--color-paper)] p-3 font-mono text-xs space-y-1.5">
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[var(--color-muted-soft)]">target</span>
          <span className="text-[var(--color-ink)] truncate">{authorship.target || targetInput || '—'}</span>
        </div>
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[var(--color-muted-soft)]">method</span>
          <span className="text-[var(--color-ink)]">{authorship.method || method}</span>
        </div>
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[var(--color-muted-soft)]">actor</span>
          <span className="text-[var(--color-ink)]">{authorship.actor ? `@${authorship.actor}` : 'guest'}</span>
        </div>
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-[var(--color-muted-soft)]">decision</span>
          <span className={authorship.verified ? 'text-[#3fbf7f]' : 'text-[#e8a33d]'}>
            {authorship.verified ? 'verified_author' : 'unverified'}
          </span>
        </div>
      </div>

      {/* Strict ownership toggle */}
      <label className="flex items-center gap-2.5 text-xs text-[var(--color-body-text)] cursor-pointer select-none">
        <input
          type="checkbox"
          checked={requireOwnership}
          onChange={(e) => onRequireOwnershipChange(e.target.checked)}
          className="w-4 h-4 accent-[#e94a32]"
        />
        <span className="inline-flex items-center gap-1.5">
          <Lock className="w-3.5 h-3.5 text-[var(--color-muted-soft)]" aria-hidden="true" />
          <span>Блокировать скан без подтверждения авторства</span>
        </span>
      </label>

      {errorMsg && (
        <p className="text-xs font-mono text-[#e94a32] leading-relaxed break-words">{errorMsg}</p>
      )}
      {!errorMsg && authorship.message && (
        <div className="text-xs font-mono text-[#3fbf7f] leading-relaxed break-words flex items-start gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
          <span>{authorship.message}</span>
        </div>
      )}

      {onAskAi && (
        <button
          type="button"
          onClick={() =>
            onAskAi(
              `Как работает проверка авторства репозитория и домена в Commit Guardian для ${targetInput || 'моего проекта'}?`
            )
          }
          className="text-xs font-mono text-[var(--color-muted-soft)] hover:text-[var(--color-ink)] underline underline-offset-4 cursor-pointer"
        >
          Спросить ИИ про защиту от несанкционированных сканов →
        </button>
      )}
    </div>
  );
}
