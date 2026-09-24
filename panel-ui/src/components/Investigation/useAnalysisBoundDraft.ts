import { useState } from 'react';

/**
 * Binds an unsaved draft to the analysis that was displayed when the analyst started it. If a refresh or
 * re-analysis later shows a different analysis, the draft is kept but must be explicitly confirmed (or
 * discarded) before it can be saved, so judgments are never silently attached to another AI run.
 */
export function useAnalysisBoundDraft(currentKey: string, hasDraft: boolean) {
  const [boundKey, setBoundKey] = useState<string | null>(null);

  // Adjust state during render (no effect) when the draft starts or is cleared.
  if (hasDraft && boundKey === null) setBoundKey(currentKey);
  if (!hasDraft && boundKey !== null) setBoundKey(null);

  return {
    changed: hasDraft && boundKey !== null && boundKey !== currentKey,
    accept: () => setBoundKey(currentKey),
  };
}
