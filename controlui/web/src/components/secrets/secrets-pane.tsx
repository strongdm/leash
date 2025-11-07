"use client";

import { Fragment, useMemo, useState, useEffect, useRef, useCallback } from "react";
import { Trash2, Check, ChevronDown } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import type { SecretRecord } from "@/lib/secrets/api";
import { useSecretDelete, useSecretUpsert, useSecretsActivationListener, useSecretsQuery } from "@/lib/secrets/hooks";

type EditingState = {
  id: string;
  field: "id" | "value";
  original: SecretRecord;
};

type SecretsPaneProps = {
  defaultOpen?: boolean;
};

// Sliding-window thresholds prevent activation animations from overwhelming the interface during rapid bursts.
const ACTIVATION_ANIMATION_DURATION_MS = 3000;
const ACTIVATION_BURST_WINDOW_MS = 600;
const ACTIVATION_BURST_THRESHOLD = 5;
const ACTIVATION_RECOVERY_THRESHOLD = 2;

export function SecretsPane({ defaultOpen = false }: SecretsPaneProps) {
  const { data: secrets = [], isLoading } = useSecretsQuery();
  const upsertMutation = useSecretUpsert();
  const deleteMutation = useSecretDelete();

  const [formName, setFormName] = useState("");
  const [formValue, setFormValue] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});
  const [editing, setEditing] = useState<EditingState | null>(null);
  const [draft, setDraft] = useState("");
  const [copiedPlaceholder, setCopiedPlaceholder] = useState<string | null>(null);
  const [open, setOpen] = useState<boolean>(defaultOpen);
  const [headerState, setHeaderState] = useState<"idle" | "active" | "suppressed">("idle");
  const [activeRowIds, setActiveRowIds] = useState<Set<string>>(new Set());
  const [animationsSuppressed, setAnimationsSuppressed] = useState(false);
  const [suppressedRowIds, setSuppressedRowIds] = useState<Set<string>>(new Set());
  const editInputRef = useRef<HTMLInputElement | null>(null);
  const animationsSuppressedRef = useRef(animationsSuppressed);
  const openRef = useRef(open);
  const activeTimersRef = useRef<Map<string, number>>(new Map());
  const activationHistoryRef = useRef<number[]>([]);
  const suppressionTimeoutRef = useRef<number | null>(null);
  const headerTimerRef = useRef<number | null>(null);

  useEffect(() => {
    openRef.current = open;
  }, [open]);

  useEffect(() => {
    animationsSuppressedRef.current = animationsSuppressed;
  }, [animationsSuppressed]);

  const restartRowAnimation = useCallback((secretId: string) => {
    setActiveRowIds((prev) => {
      if (!prev.has(secretId)) {
        return prev;
      }
      const next = new Set(prev);
      next.delete(secretId);
      return next;
    });

    const addBack = () => {
      setActiveRowIds((prev) => {
        const next = new Set(prev);
        next.add(secretId);
        return next;
      });
    };

    if (typeof window === "undefined") {
      addBack();
      return;
    }

    if (typeof window.requestAnimationFrame === "function") {
      window.requestAnimationFrame(() => {
        addBack();
      });
      return;
    }

    window.setTimeout(() => {
      addBack();
    }, 16);
  }, []);

  const scheduleRowFade = useCallback((id: string) => {
    setSuppressedRowIds((prev) => {
      if (!prev.has(id)) {
        return prev;
      }
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
    const timers = activeTimersRef.current;
    const existing = timers.get(id);
    if (existing) {
      clearTimeout(existing);
    }
    const timer = window.setTimeout(() => {
      timers.delete(id);
      setActiveRowIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }, ACTIVATION_ANIMATION_DURATION_MS);
    timers.set(id, timer);
  }, []);

  const releaseSuppression = useCallback(() => {
    setAnimationsSuppressed(false);
    setHeaderState("idle");
    const timers = activeTimersRef.current;
    timers.forEach((timerId) => {
      clearTimeout(timerId);
    });
    timers.clear();
  }, []);

  const scheduleSuppressionRelease = useCallback(() => {
    if (suppressionTimeoutRef.current !== null) {
      return;
    }

    suppressionTimeoutRef.current = window.setTimeout(() => {
      suppressionTimeoutRef.current = null;
      const now = Date.now();
      const history = activationHistoryRef.current;
      while (history.length > 0 && now - history[0] > ACTIVATION_BURST_WINDOW_MS) {
        history.shift();
      }

      if (history.length < ACTIVATION_RECOVERY_THRESHOLD) {
        releaseSuppression();
      } else {
        scheduleSuppressionRelease();
      }
    }, ACTIVATION_BURST_WINDOW_MS);
  }, [releaseSuppression]);

  // Handle activation animation - CLEAN version
  const handleActivation = useCallback((secretId?: string) => {
    const now = Date.now();
    const history = activationHistoryRef.current;
    history.push(now);

    while (history.length > 0 && now - history[0] > ACTIVATION_BURST_WINDOW_MS) {
      history.shift();
    }

    const burstActive = history.length >= ACTIVATION_BURST_THRESHOLD;
    if (burstActive) {
      setAnimationsSuppressed(true);
      setHeaderState("suppressed");
      if (headerTimerRef.current) {
        clearTimeout(headerTimerRef.current);
        headerTimerRef.current = null;
      }
      scheduleSuppressionRelease();
    }
    if (!burstActive && animationsSuppressedRef.current) {
      releaseSuppression();
    }

    const isOpen = openRef.current;
    console.log("[SecretsPane] Activation detected! secretId:", secretId, "open:", isOpen);

    if (isOpen && secretId) {
      // Animate the specific row
      console.log("[SecretsPane] Animating row:", secretId);
      restartRowAnimation(secretId);
      setSuppressedRowIds((prev) => {
        const next = new Set(prev);
        if (burstActive) {
          next.add(secretId);
        } else {
          next.delete(secretId);
        }
        return next;
      });
      if (burstActive) {
        const timers = activeTimersRef.current;
        const existing = timers.get(secretId);
        if (existing) {
          clearTimeout(existing);
          timers.delete(secretId);
        }
      } else {
        scheduleRowFade(secretId);
      }
    } else {
      // Animate the header
      console.log("[SecretsPane] Animating header");
      if (burstActive) {
        setHeaderState("suppressed");
      } else {
        setHeaderState("active");
        if (headerTimerRef.current) {
          clearTimeout(headerTimerRef.current);
        }
        headerTimerRef.current = window.setTimeout(() => {
          setHeaderState((prev) => (prev === "active" ? "idle" : prev));
          headerTimerRef.current = null;
        }, ACTIVATION_ANIMATION_DURATION_MS); // 0.5s flicker + 2s hold + 0.5s fade = 3s total
      }
    }
  }, [scheduleSuppressionRelease, releaseSuppression, scheduleRowFade, restartRowAnimation]);

  useSecretsActivationListener(true, handleActivation);

  useEffect(() => {
    const timers = activeTimersRef.current;
    return () => {
      timers.forEach((timerId) => {
        clearTimeout(timerId);
      });
      timers.clear();

      const suppressionTimer = suppressionTimeoutRef.current;
      if (suppressionTimer !== null) {
        clearTimeout(suppressionTimer);
        suppressionTimeoutRef.current = null;
      }

      const headerTimer = headerTimerRef.current;
      if (headerTimer !== null) {
        clearTimeout(headerTimer);
        headerTimerRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (editing && editInputRef.current) {
      editInputRef.current.focus();
      editInputRef.current.select();
    }
  }, [editing]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const handleToggleShortcut = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();

      // Check for Ctrl+Alt+S (works on macOS as Ctrl+Option+S and on Windows/Linux as Ctrl+Alt+S)
      if (event.ctrlKey && event.altKey && !event.metaKey && !event.shiftKey && key === "s") {
        event.preventDefault();
        event.stopPropagation();
        setOpen((prev) => !prev);
        return;
      }

      // Check for Cmd+Ctrl+S on macOS
      if (event.metaKey && event.ctrlKey && !event.altKey && !event.shiftKey && key === "s") {
        event.preventDefault();
        event.stopPropagation();
        setOpen((prev) => !prev);
        return;
      }
    };

    window.addEventListener("keydown", handleToggleShortcut);
    return () => window.removeEventListener("keydown", handleToggleShortcut);
  }, []);

  const sortedSecrets = useMemo(() => {
    return [...secrets].sort((a, b) => a.id.localeCompare(b.id));
  }, [secrets]);

  const resetEditing = () => {
    setEditing(null);
    setDraft("");
  };

  const clearRowError = (id: string) => {
    setRowErrors((prev) => {
      if (!prev[id]) return prev;
      const next = { ...prev };
      delete next[id];
      return next;
    });
  };

  const beginEdit = (secret: SecretRecord, field: "id" | "value") => {
    clearRowError(secret.id);
    setEditing({ id: secret.id, field, original: secret });
    setDraft(field === "id" ? secret.id : secret.value);
  };

  const handleAddSecret = async (event: React.FormEvent) => {
    event.preventDefault();
    const name = formName.trim();
    if (name.length === 0) {
      setFormError("Name is required");
      return;
    }
    if (formValue.length === 0) {
      setFormError("Value is required");
      return;
    }
    setFormError(null);
    try {
      await upsertMutation.mutateAsync({ pathId: name, payload: { id: name, value: formValue } });
      setFormName("");
      setFormValue("");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to add secret";
      setFormError(message);
    }
  };

  const handleDelete = async (secret: SecretRecord) => {
    clearRowError(secret.id);
    try {
      await deleteMutation.mutateAsync({ id: secret.id });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to delete secret";
      setRowErrors((prev) => ({ ...prev, [secret.id]: message }));
    }
  };

  const commitEdit = async () => {
    if (!editing) return;
    const { field, original } = editing;
    const trimmed = field === "id" ? draft.trim() : draft;
    if (field === "id" && trimmed === original.id) {
      resetEditing();
      return;
    }
    if (field === "value" && trimmed === original.value) {
      resetEditing();
      return;
    }
    if (field === "id" && trimmed.length === 0) {
      setRowErrors((prev) => ({ ...prev, [original.id]: "Name is required" }));
      return;
    }

    clearRowError(original.id);
    try {
      if (field === "id") {
        await upsertMutation.mutateAsync({
          pathId: original.id,
          payload: { id: trimmed, value: original.value },
        });
      } else {
        await upsertMutation.mutateAsync({
          pathId: original.id,
          payload: { id: original.id, value: trimmed },
        });
      }
      resetEditing();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to update secret";
      setRowErrors((prev) => ({ ...prev, [original.id]: message }));
    }
  };

  const handleEditKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      void commitEdit();
    } else if (event.key === "Escape") {
      event.preventDefault();
      resetEditing();
    }
  };

  const handleCopyPlaceholder = async (placeholder: string) => {
    try {
      await navigator.clipboard.writeText(placeholder);
      setCopiedPlaceholder(placeholder);
      setTimeout(() => setCopiedPlaceholder(null), 1500);
    } catch (err) {
      console.error("Failed to copy placeholder:", err);
    }
  };

  return (
    <div className={cn(
      "rounded-lg border",
      headerState === "active"
        ? "border-[#7A67E6] bg-[#7A67E6]/10 animate-[flicker_0.5s_ease-out_forwards,_colorhold_2s_ease-out_0.5s_forwards,_fadeout_0.5s_ease-out_2.5s_forwards]"
        : headerState === "suppressed"
          ? "border-[#7A67E6] bg-[#7A67E6]/20 transition-colors duration-300"
        : "border-cyan-500/30 bg-slate-900/60 transition-all duration-300"
    )}>
      <div
        className="w-full px-4 py-3 flex items-center justify-between gap-3 text-left hover:bg-slate-900/70 cursor-pointer"
        role="button"
        tabIndex={0}
        aria-expanded={open}
        aria-controls="secrets-panel"
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
      >
        <div className="flex-1">
          <div className={cn(
            "text-sm font-semibold tracking-wide",
            headerState === "active" || headerState === "suppressed" ? "text-[#B859E0]" : "text-cyan-300"
          )}>Secrets</div>
          <p className="text-xs text-slate-300/80">Manage secrets applied to network requests.</p>
        </div>
        <div className="flex items-center gap-2">
          {process.env.NODE_ENV === "development" && (
            <Button
              size="sm"
              variant="outline"
              onClick={(e) => {
                e.stopPropagation();
                // Test with the first secret if pane is open, otherwise test header
                const testSecretId = open && sortedSecrets.length > 0 ? sortedSecrets[0].id : undefined;
                handleActivation(testSecretId);
              }}
              className="text-xs"
            >
              Test Animation
            </Button>
          )}
          <ChevronDown className={cn(
            "size-4 transition-transform",
            open ? "rotate-180" : "rotate-0"
          )} />
        </div>
      </div>

      {open && (
        <div id="secrets-panel" className="px-4 pb-4 space-y-4">
        <form className="grid gap-3 md:grid-cols-[1fr_2fr_auto]" onSubmit={handleAddSecret}>
          <div className="flex flex-col gap-1">
            <label className="text-sm font-medium" htmlFor="secret-name">
              Name
            </label>
            <Input
              id="secret-name"
              autoComplete="off"
              value={formName}
              disabled={upsertMutation.isPending}
              onChange={(event) => setFormName(event.target.value)}
              placeholder="database_password"
            />
          </div>
          <div className="flex flex-col gap-1 md:col-span-1">
            <label className="text-sm font-medium" htmlFor="secret-value">
              Value
            </label>
            <Input
              id="secret-value"
              autoComplete="off"
              value={formValue}
              disabled={upsertMutation.isPending}
              onChange={(event) => setFormValue(event.target.value)}
              placeholder="super-secret-value"
            />
          </div>
          <div className="flex items-end md:pl-4">
            <Button type="submit" disabled={upsertMutation.isPending}>
              Add
            </Button>
          </div>
        </form>
        {formError ? <p className="text-sm text-destructive">{formError}</p> : null}
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading secrets…</p>
        ) : sortedSecrets.length === 0 ? (
          <p className="text-sm text-muted-foreground">No secrets defined yet.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-24">Activations</TableHead>
                <TableHead className="w-52">Name</TableHead>
                <TableHead>Secret</TableHead>
                <TableHead>Placeholder</TableHead>
                <TableHead className="w-14 text-right">&nbsp;</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedSecrets.map((secret) => {
                const isEditing = editing && editing.original.id === secret.id;
                const rowError = rowErrors[secret.id];
                const isActive = activeRowIds.has(secret.id);
                const isSuppressed = suppressedRowIds.has(secret.id) || (animationsSuppressed && isActive);
                const highlightClass = isSuppressed
                  ? "bg-[#7A67E6]/20 transition-colors duration-300"
                  : (isActive
                    ? "bg-[#7A67E6]/10 animate-[flicker_0.5s_ease-out_forwards,_colorhold_2s_ease-out_0.5s_forwards,_fadeout_0.5s_ease-out_2.5s_forwards]"
                    : null);

                return (
                  <Fragment key={secret.id}>
                    <TableRow className={cn(
                      isEditing && "bg-muted/40",
                      highlightClass
                    )}>
                      <TableCell>
                        <span className={cn(
                          "text-sm text-muted-foreground",
                          (isSuppressed || isActive) && "text-[#B859E0] font-semibold"
                        )}>{secret.activations}</span>
                      </TableCell>
                      <TableCell>
                        {isEditing && editing?.field === "id" ? (
                          <Input
                            ref={(node) => {
                              editInputRef.current = node;
                            }}
                            value={draft}
                            onChange={(event) => setDraft(event.target.value)}
                            onKeyDown={handleEditKeyDown}
                            onBlur={resetEditing}
                            aria-label={`Edit name for ${editing.original.id}`}
                          />
                        ) : (
                          <button
                            type="button"
                            className={cn(
                              "text-sm font-medium text-left text-foreground rounded px-2 py-1 -mx-2 -my-1",
                              "border border-transparent hover:border-primary/50 hover:bg-muted/50",
                              "transition-colors"
                            )}
                            onClick={() => beginEdit(secret, "id")}
                            aria-label={`Edit name ${secret.id}`}
                          >
                            {secret.id}
                          </button>
                        )}
                      </TableCell>
                      <TableCell className="max-w-md">
                        {isEditing && editing?.field === "value" ? (
                          <Input
                            ref={(node) => {
                              editInputRef.current = node;
                            }}
                            value={draft}
                            onChange={(event) => setDraft(event.target.value)}
                            onKeyDown={handleEditKeyDown}
                            onBlur={resetEditing}
                            aria-label={`Edit value for ${editing.original.id}`}
                          />
                        ) : (
                          <button
                            type="button"
                            className={cn(
                              "text-left text-sm font-mono text-muted-foreground rounded px-2 py-1 -mx-2 -my-1",
                              "border border-transparent hover:border-primary/50 hover:bg-muted/50",
                              "transition-colors max-w-full truncate block"
                            )}
                            onClick={() => beginEdit(secret, "value")}
                            aria-label={`Edit value ${secret.id}`}
                            title={secret.value}
                          >
                            {secret.value || <span className="italic text-muted-foreground">(empty)</span>}
                          </button>
                        )}
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <Tooltip open={copiedPlaceholder === secret.placeholder ? true : undefined}>
                          <TooltipTrigger asChild>
                            <button
                              type="button"
                              className={cn(
                                "font-mono text-sm text-muted-foreground rounded px-2 py-1 -mx-2 -my-1",
                                "border border-transparent hover:border-primary/50 hover:bg-muted/50",
                                "transition-all cursor-pointer inline-flex items-center gap-1.5 max-w-full",
                                copiedPlaceholder === secret.placeholder && "border-primary bg-primary/10 text-primary"
                              )}
                              onClick={() => void handleCopyPlaceholder(secret.placeholder)}
                              aria-label={`Copy placeholder ${secret.placeholder}`}
                              aria-live="polite"
                              aria-atomic="true"
                            >
                              <span className="truncate">{secret.placeholder}</span>
                              {copiedPlaceholder === secret.placeholder && (
                                <Check className="size-3 flex-shrink-0 animate-in fade-in zoom-in duration-200" />
                              )}
                            </button>
                          </TooltipTrigger>
                          <TooltipContent>
                            {copiedPlaceholder === secret.placeholder ? "Copied!" : "Copy placeholder to clipboard"}
                          </TooltipContent>
                        </Tooltip>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete secret ${secret.id}`}
                          onClick={() => void handleDelete(secret)}
                          disabled={deleteMutation.isPending && deleteMutation.variables?.id === secret.id}
                          className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                    {rowError ? (
                      <TableRow>
                        <TableCell colSpan={5}>
                          <p className="text-sm text-destructive">{rowError}</p>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        )}
        </div>
      )}
    </div>
  );
}

export default SecretsPane;
