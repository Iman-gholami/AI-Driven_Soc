import { useCallback, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api, getApiErrorInfo, type ApiErrorInfo } from '../../api/client';
import type { InvestigationWriteResult } from '../../types/investigation';
import { newIdempotencyKey } from './investigationFormat';

export type SaveStatus =
  | { state: 'idle' }
  | { state: 'saving' }
  | { state: 'saved'; replayed: boolean; sequence: number }
  | { state: 'error'; error: ApiErrorInfo };

type Kind = 'review' | 'disposition' | 'notes' | 'reopen';

/**
 * Submits one investigation form. The idempotency key stays the same while the draft is unchanged, so a
 * retry after a network failure cannot create a second event; editing the draft or a successful save
 * starts a new key. The caller keeps the draft, so input survives failures and conflicts.
 */
export function useInvestigationSubmission(alertId: string, kind: Kind) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<SaveStatus>({ state: 'idle' });
  const keyRef = useRef<{ draft: string; key: string } | null>(null);

  const submit = useCallback(
    async (body: Record<string, unknown>): Promise<InvestigationWriteResult | null> => {
      const draft = JSON.stringify(body);
      if (!keyRef.current || keyRef.current.draft !== draft)
        keyRef.current = { draft, key: newIdempotencyKey() };

      setStatus({ state: 'saving' });
      try {
        const result = await api.recordInvestigationEvent(alertId, kind, body, keyRef.current.key);
        keyRef.current = null;
        setStatus({ state: 'saved', replayed: result.replayed, sequence: result.event.sequence });
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ['investigation', alertId] }),
          queryClient.invalidateQueries({ queryKey: ['alerts'] }),
          queryClient.invalidateQueries({ queryKey: ['alert', alertId] }),
          queryClient.invalidateQueries({ queryKey: ['analyst-feedback'] }),
          queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] }),
        ]);
        return result;
      } catch (error) {
        setStatus({ state: 'error', error: getApiErrorInfo(error, 'Unable to save') });
        return null;
      }
    },
    [alertId, kind, queryClient],
  );

  const reset = useCallback(() => setStatus({ state: 'idle' }), []);
  return { status, submit, reset };
}
