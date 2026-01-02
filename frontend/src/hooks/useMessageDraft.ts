import { useState, useEffect, useCallback, useRef } from "react";

const DRAFT_KEY_PREFIX = "chat_draft_";
const DRAFT_SAVE_DELAY = 500; // ms debounce

export interface DraftData {
  content: string;
  replyToId?: number;
  replyToUsername?: string;
  savedAt: number;
}

/**
 * Hook to manage message drafts with auto-save to localStorage
 */
export function useMessageDraft(conversationId: number | undefined) {
  const [draft, setDraft] = useState<DraftData | null>(null);
  const [hasDraft, setHasDraft] = useState(false);
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastSavedRef = useRef<string>("");

  const storageKey = conversationId ? `${DRAFT_KEY_PREFIX}${conversationId}` : null;

  // Load draft from localStorage when conversation changes
  useEffect(() => {
    if (!storageKey) {
      setDraft(null);
      setHasDraft(false);
      return;
    }

    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        const parsed = JSON.parse(stored) as DraftData;
        // Only restore drafts less than 7 days old
        const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
        if (parsed.savedAt > weekAgo && parsed.content.trim()) {
          setDraft(parsed);
          setHasDraft(true);
          lastSavedRef.current = parsed.content;
          return;
        } else {
          // Remove stale draft
          localStorage.removeItem(storageKey);
        }
      }
    } catch (e) {
      console.error("Failed to load draft:", e);
    }

    setDraft(null);
    setHasDraft(false);
  }, [storageKey]);

  // Save draft to localStorage (debounced)
  const saveDraft = useCallback(
    (content: string, replyToId?: number, replyToUsername?: string) => {
      if (!storageKey) return;

      // Clear pending save
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }

      // Don't save if content hasn't changed
      if (content === lastSavedRef.current && !replyToId) return;

      saveTimeoutRef.current = setTimeout(() => {
        try {
          if (content.trim()) {
            const draftData: DraftData = {
              content,
              replyToId,
              replyToUsername,
              savedAt: Date.now(),
            };
            localStorage.setItem(storageKey, JSON.stringify(draftData));
            setDraft(draftData);
            setHasDraft(true);
            lastSavedRef.current = content;
          } else {
            // Clear draft if empty
            localStorage.removeItem(storageKey);
            setDraft(null);
            setHasDraft(false);
            lastSavedRef.current = "";
          }
        } catch (e) {
          console.error("Failed to save draft:", e);
        }
      }, DRAFT_SAVE_DELAY);
    },
    [storageKey]
  );

  // Clear draft (after sending message)
  const clearDraft = useCallback(() => {
    if (!storageKey) return;

    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }

    try {
      localStorage.removeItem(storageKey);
    } catch (e) {
      console.error("Failed to clear draft:", e);
    }

    setDraft(null);
    setHasDraft(false);
    lastSavedRef.current = "";
  }, [storageKey]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
    };
  }, []);

  return {
    draft,
    hasDraft,
    saveDraft,
    clearDraft,
  };
}

/**
 * Get all conversations with drafts
 */
export function getAllDraftConversations(): number[] {
  const draftConversations: number[] = [];
  
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(DRAFT_KEY_PREFIX)) {
        const conversationId = parseInt(key.replace(DRAFT_KEY_PREFIX, ""), 10);
        if (!isNaN(conversationId)) {
          const stored = localStorage.getItem(key);
          if (stored) {
            const parsed = JSON.parse(stored) as DraftData;
            const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
            if (parsed.savedAt > weekAgo && parsed.content.trim()) {
              draftConversations.push(conversationId);
            }
          }
        }
      }
    }
  } catch (e) {
    console.error("Failed to get draft conversations:", e);
  }

  return draftConversations;
}

/**
 * Format draft preview text
 */
export function formatDraftPreview(content: string, maxLength: number = 50): string {
  const text = content.replace(/\n/g, " ").trim();
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 3) + "...";
}

export default useMessageDraft;
