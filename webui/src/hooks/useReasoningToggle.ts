import { useState, useMemo } from 'react';

/**
 * Shared hook for reasoning/thinking toggle logic.
 *
 * Used by both Session/MessageBubble and ChatDialog/DialogMessageBubble
 * to avoid duplicating the expand/collapse state management.
 *
 * Rules:
 * - While reasoning is in progress (no text/tool part yet) → always expanded
 * - Once reasoning is done (text or tool part exists, or message finished) → collapsed by default
 * - User can manually toggle (collapse/expand) each reasoning block independently
 */
export function useReasoningToggle(
  parts: any[],
  messageFinish?: any,
) {
  // Check if a text part already exists → reasoning is done
  const hasTextPart = useMemo(
    () => parts.some((p: any) => p.type === 'text' && p.text),
    [parts],
  );

  // Check if a tool part exists → reasoning is also done (e.g. reasoning + tool call, no text)
  const hasToolPart = useMemo(
    () => parts.some((p: any) => p.type === 'tool' || p.type === 'toolCall'),
    [parts],
  );

  const hasReasoningPart = useMemo(
    () => parts.some((p: any) => (p.type === 'reasoning' || p.type === 'thinking') && (p.text || p.thinking)),
    [parts],
  );

  const isReasoningDone = !!messageFinish || hasTextPart || hasToolPart;

  // Per-part expanded state: keyed by part ID or index string
  const [expandedByKey, setExpandedByKey] = useState<Record<string, boolean>>({});

  /**
   * Get the display state for a specific reasoning part.
   * - reasoning in progress → expanded (true)
   * - reasoning done → expanded by default, user can collapse manually
   */
  const getPartExpanded = (partKey: string): boolean => {
    if (!isReasoningDone) return true;
    // 思考结束后默认折叠，用户可手动展开
    return expandedByKey[partKey] ?? false;
  };

  /**
   * Toggle a specific reasoning part's expanded state.
   * Only works after reasoning is done.
   */
  const togglePart = (partKey: string) => {
    if (!isReasoningDone) return;
    setExpandedByKey((prev) => ({
      ...prev,
      [partKey]: !(prev[partKey] ?? true),
    }));
  };

  return {
    getPartExpanded,
    togglePart,
    isReasoningDone,
    hasTextPart,
  };
}
