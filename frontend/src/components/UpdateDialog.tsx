import { useCallback, useEffect, useRef, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Terminal } from "lucide-react";
import { useTranslation } from "react-i18next";
import { BASE_URL, getAuthHeaders, handleUnauthorizedResponse } from "@/api";

interface UpdateDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

const MAX_UPDATE_LOGS = 500;

export function UpdateDialog({ open, onOpenChange }: UpdateDialogProps) {
    const { t } = useTranslation();
    const [logs, setLogs] = useState<string[]>([]);
    const [status, setStatus] = useState<"idle" | "connecting" | "connected" | "error" | "complete">("idle");
    const abortRef = useRef<AbortController | null>(null);
    const bottomRef = useRef<HTMLDivElement>(null);
    const startedRef = useRef(false);

    const appendLog = useCallback((message: string) => {
        setLogs(prev => {
            const next = [...prev, message];
            return next.length > MAX_UPDATE_LOGS ? next.slice(-MAX_UPDATE_LOGS) : next;
        });
    }, []);

    const startUpdate = useCallback(async () => {
        setLogs([]);
        try {
            const authHeaders = getAuthHeaders();
            if (!authHeaders["Authorization"]) {
                appendLog(`❌ ${t('common.error')}: No auth token`);
                setStatus("error");
                return;
            }
            const res = await fetch(`${BASE_URL}/deploy/webhook`, {
                method: "POST",
                headers: authHeaders,
            });

            if (handleUnauthorizedResponse(res)) return;

            if (!res.ok) {
                const detail = (await res.text()).trim() || res.statusText;
                appendLog(`❌ ${t('common.error')}: ${detail}`);
                setStatus("error");
                return;
            }

            appendLog(`✅ ${t('update.success_trigger')}`);
            setStatus("connecting");

            const controller = new AbortController();
            abortRef.current = controller;

            const streamResp = await fetch(`${BASE_URL}/deploy/logs`, {
                headers: authHeaders,
                signal: controller.signal,
            });

            if (handleUnauthorizedResponse(streamResp)) return;

            if (!streamResp.ok || !streamResp.body) {
                const detail = (await streamResp.text()).trim() || t('update.ws_error');
                appendLog(`❌ ${detail}`);
                setStatus("error");
                return;
            }

            setStatus("connected");
            appendLog(`📡 ${t('update.ws_connected')}`);

            const reader = streamResp.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split("\n");
                buffer = lines.pop() ?? "";

                for (const line of lines) {
                    const normalized = line.replace(/\r$/, "");
                    if (!normalized.startsWith("data:")) continue;

                    const eventData = normalized.slice(5).trimStart();
                    if (!eventData) continue;

                    appendLog(eventData);
                    if (eventData.includes("Update complete!")) {
                        setStatus("complete");
                        controller.abort();
                        return;
                    }
                    if (eventData.includes("Update failed")) {
                        setStatus("error");
                        controller.abort();
                        return;
                    }
                }
            }

            appendLog(`🔌 ${t('update.ws_closed')}`);

        } catch (e: unknown) {
            if (e instanceof DOMException && e.name === "AbortError") return;
            const message = e instanceof Error ? e.message : String(e);
            appendLog(`❌ Exception: ${message}`);
            setStatus("error");
        }
    }, [appendLog, t]);

    useEffect(() => {
        if (!open) {
            if (abortRef.current) {
                abortRef.current.abort();
                abortRef.current = null;
            }
            startedRef.current = false;
            return;
        }

        if (!startedRef.current) {
            startedRef.current = true;
            const startTimer = window.setTimeout(() => {
                startUpdate();
            }, 0);
            return () => window.clearTimeout(startTimer);
        }
    }, [open, startUpdate]);

    useEffect(() => {
        return () => {
            if (abortRef.current) {
                abortRef.current.abort();
                abortRef.current = null;
            }
        };
    }, []);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    useEffect(() => {
        if (status !== "complete") return;
        const timer = window.setTimeout(() => window.location.reload(), 5000);
        return () => window.clearTimeout(timer);
    }, [status]);

    const handleOpenChange = (nextOpen: boolean) => {
        if (!nextOpen) {
            setStatus("idle");
        }
        onOpenChange(nextOpen);
    };

    return (
        <Dialog open={open} onOpenChange={handleOpenChange}>
            <DialogContent className="sm:max-w-[600px] bg-background">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Terminal className="h-5 w-5" />
                        {t('update.title')}
                    </DialogTitle>
                </DialogHeader>

                <div className="mt-4 bg-muted/50 p-4 rounded-md h-[400px] overflow-y-auto font-mono text-xs space-y-1 border">
                    {logs.map((log, i) => (
                        <div key={i} className={`break-words ${log.includes("❌") ? "text-red-500" : log.includes("✅") ? "text-emerald-500" : "text-foreground"}`}>
                            {log}
                        </div>
                    ))}
                    <div ref={bottomRef} />
                </div>

                {status === "complete" && (
                    <div className="mt-4 p-4 bg-emerald-500/10 text-emerald-600 rounded-md text-sm text-center font-medium">
                        {t('update.success_complete')}
                    </div>
                )}
            </DialogContent>
        </Dialog>
    );
}
