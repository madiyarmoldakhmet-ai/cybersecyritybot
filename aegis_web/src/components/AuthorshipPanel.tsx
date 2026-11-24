'use client';

import { useState } from 'react';
import { Check, Copy, ExternalLink, KeyRound, Loader2, Lock, ShieldCheck } from 'lucide-react';
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

export interface PendingVerifyChallenge {
  repoName: string;
  challengeCode: string;
  verifyUrl: string;
  verifyFilename?: string;
}

interface AuthorshipPanelProps {
  targetInput: string;
  onTargetInputChange: (val: string) => void;
  authorship: AuthorshipState;
  onAuthorshipChange: (next: AuthorshipState) => void;
  pendingVerify?: PendingVerifyChallenge | null;
  onChallengeIssued?: (challenge: PendingVerifyChallenge) => void;
  onVerifiedAutoScan?: (target: string, proofToken: string, githubToken?: string) => void;
  onAskAi?: (prompt: string) => void;
}

type VerifyMethod = 'challenge' | 'token' | 'dns_txt';

export function AuthorshipPanel({
  targetInput,
  onTargetInputChange,
  authorship,
  onAuthorshipChange,
  pendingVerify,
  onChallengeIssued,
  onVerifiedAutoScan,
  onAskAi,
}: AuthorshipPanelProps) {
  const [method, setMethod] = useState<VerifyMethod>('challenge');
  const [tokenInput, setTokenInput] = useState(authorship.githubToken || '');
  const [localChallengeCode, setLocalChallengeCode] = useState('');
  const [localVerifyUrl, setLocalVerifyUrl] = useState('');
  const [instructions, setInstructions] = useState<string[]>([]);
  const [loadingChallenge, setLoadingChallenge] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [copied, setCopied] = useState(false);

  const challengeCode = localChallengeCode || pendingVerify?.challengeCode || '';
  const verifyUrl = localVerifyUrl || pendingVerify?.verifyUrl || '';

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
      const nextCode = data.challenge_code || '';
      const nextUrl = data.verify_url || '';
      setLocalChallengeCode(nextCode);
      setLocalVerifyUrl(nextUrl);
      setInstructions(Array.isArray(data.instructions) ? data.instructions : []);
      if (targetType === 'github' && nextCode && nextUrl && onChallengeIssued) {
        onChallengeIssued({
          repoName: data.target || cleanTarget,
          challengeCode: nextCode,
          verifyUrl: nextUrl,
          verifyFilename: data.verify_filename || 'verify.txt',
        });
      }
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
      setErrorMsg('Вставьте GitHub Personal Access Token (или выберите 1-клик проверку без токена).');
      return;
    }
    if (method !== 'token' && !challengeCode.trim()) {
      setErrorMsg('Сначала нажмите «Получить кнопку», нажмите Commit на GitHub и затем проверьте.');
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
      const nextState: AuthorshipState = {
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
      };
      onAuthorshipChange(nextState);
      if (data.verified && nextState.targetType === 'github' && onVerifiedAutoScan) {
        onVerifiedAutoScan(nextState.target, nextState.proofToken, nextState.githubToken);
      }
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
            'font-mono text-[11px] px-2 py-0.5 border-2',
            authorship.verified
              ? 'border-[#47d18c] text-[#47d18c] bg-[#47d18c]/15'
              : 'border-[var(--color-line-strong)] text-[var(--color-muted-soft)] bg-[var(--color-raised)]'
          )}
        >
          {authorship.verified ? `VERIFIED · ${authorship.role}` : 'UNVERIFIED'}
        </span>
      </div>

      {/* Method switcher pixel tabs */}
      <div className="grid grid-cols-3 gap-1.5" role="group" aria-label="Способ подтверждения авторства">
        {(
          [
            { id: 'challenge', label: '1-клик GitHub' },
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
              'pixel-btn min-h-8 px-2 py-1 font-mono text-[11px] cursor-pointer truncate',
              method === item.id
                ? '!border-[#e94a32] bg-[#e94a32]/20 text-[var(--color-ink)] font-semibold'
                : 'bg-[var(--color-panel)] text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]'
            )}
          >
            {item.label}
          </button>
        ))}
      </div>

      {/* Target input */}
      <div className="space-y-1.5">
        <label htmlFor="cg-verify-target" className="block font-mono text-[11.5px] text-[var(--color-muted-soft)]">
          {method === 'dns_txt' ? 'Домен для DAST-аудита' : 'GitHub репозиторий (URL или owner/repo)'}
        </label>
        <input
          id="cg-verify-target"
          type="text"
          value={targetInput}
          onChange={(e) => onTargetInputChange(e.target.value)}
          placeholder={method === 'dns_txt' ? 'app.fintech.kz' : 'https://github.com/owner/repo'}
          className="pixel-input w-full min-h-9 px-3 py-1.5 bg-[var(--color-panel)] focus:border-[#56d4b2] text-sm font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
        />
      </div>

      {method === 'token' ? (
        <div className="space-y-2">
          <label htmlFor="cg-gh-token" className="block font-mono text-[11.5px] text-[var(--color-muted-soft)]">
            Personal Access Token (подходит и для приватных репо, не хранится на сервере)
          </label>
          <input
            id="cg-gh-token"
            type="password"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="ghp_... или github_pat_..."
            className="pixel-input w-full min-h-9 px-3 py-1.5 bg-[var(--color-panel)] focus:border-[#56d4b2] text-sm font-mono text-[var(--color-ink)] placeholder:text-[var(--color-faint)] focus:outline-none"
          />
          <button
            type="button"
            disabled={verifying}
            onClick={handleVerify}
            className="pixel-btn-snow w-full min-h-9 px-3.5 py-2 font-mono text-xs uppercase tracking-wider inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <KeyRound className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{verifying ? 'Проверяю права…' : 'Проверить и запустить аудит'}</span>
          </button>
        </div>
      ) : (
        <div className="space-y-2.5">
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={loadingChallenge}
              onClick={handleIssueChallenge}
              className="pixel-btn flex-1 min-h-9 px-3 py-1.5 bg-[var(--color-raised)] font-mono text-xs text-[var(--color-ink)] cursor-pointer"
            >
              {loadingChallenge ? 'Готовлю…' : challengeCode ? 'Обновить код' : '1. Получить кнопку'}
            </button>
            <button
              type="button"
              disabled={verifying || !challengeCode}
              onClick={handleVerify}
              className="pixel-btn-snow flex-1 min-h-9 px-3 py-1.5 font-mono text-xs cursor-pointer disabled:opacity-45"
            >
              {verifying ? 'Проверка…' : 'Проверить сейчас'}
            </button>
          </div>

          {challengeCode && (
            <div className="pixel-panel bg-[var(--color-panel)] p-3 space-y-2.5">
              {method === 'challenge' && verifyUrl && (
                <a
                  href={verifyUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="pixel-btn-primary w-full min-h-9 px-3 py-2 font-mono text-xs font-semibold inline-flex items-center justify-center gap-1.5"
                >
                  <span>Открыть GitHub и нажать Commit</span>
                  <ExternalLink className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                </a>
              )}

              <div className="flex items-center justify-between gap-2">
                <code className="text-xs text-[#ff7b66] break-all">{challengeCode}</code>
                <button
                  type="button"
                  onClick={handleCopyCode}
                  aria-label="Скопировать код подтверждения"
                  className="pixel-btn min-h-7 px-2 py-0.5 bg-[var(--color-paper)] font-mono text-[11px] inline-flex items-center gap-1 cursor-pointer text-[var(--color-muted-soft)] hover:text-[var(--color-ink)]"
                >
                  {copied ? <Check className="w-3 h-3 text-[#47d18c]" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Скопировано' : 'Копия'}</span>
                </button>
              </div>

              {pendingVerify && method === 'challenge' && (
                <div className="flex items-center gap-1.5 font-mono text-[11.5px] text-[#56d4b2]">
                  <Loader2 className="w-3 h-3 animate-spin shrink-0" aria-hidden="true" />
                  <span>Авто-проверка активна — скан стартует сам после Commit</span>
                </div>
              )}

              {instructions.length > 0 && (
                <ul className="space-y-1 font-mono text-[11.5px] text-[var(--color-muted-soft)] leading-relaxed">
                  {instructions.map((line, i) => (
                    <li key={i} className="break-words">{line}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {/* Structured Inspection Rows */}
      <div className="pixel-panel bg-[var(--color-panel)] p-3 font-mono text-xs space-y-1.5">
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
          <span className={authorship.verified ? 'text-[#47d18c]' : 'text-[#f0b541]'}>
            {authorship.verified ? 'verified_author' : 'unverified'}
          </span>
        </div>
      </div>

      {/* Mandatory ownership policy indicator */}
      <div className="border-2 border-[#e94a32] bg-[#e94a32]/12 px-3 py-2 flex items-start gap-2 text-xs text-[var(--color-body-text)]">
        <Lock className="w-3.5 h-3.5 text-[#ff7b66] shrink-0 mt-0.5" aria-hidden="true" />
        <span>
          <strong className="text-[var(--color-ink)]">Обязательная проверка авторства активна:</strong>{' '}
          сканирование чужих GitHub-репозиториев заблокировано. Без своего репо доступен «Демо-аудит» и загрузка .zip.
        </span>
      </div>

      {errorMsg && (
        <p className="text-xs font-mono text-[#ff7b66] leading-relaxed break-words">{errorMsg}</p>
      )}
      {!errorMsg && authorship.message && (
        <div className="text-xs font-mono text-[#47d18c] leading-relaxed break-words flex items-start gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
          <span>{authorship.message}</span>
        </div>
      )}

      {onAskAi && (
        <button
          type="button"
          onClick={() => onAskAi('Как работает проверка авторства и почему нельзя сканировать чужие репозитории?')}
          className="text-xs font-mono text-[var(--color-muted-soft)] hover:text-[#56d4b2] transition-colors cursor-pointer"
        >
          Спросить ИИ про защиту от несанкционированных сканов →
        </button>
      )}
    </div>
  );
}
