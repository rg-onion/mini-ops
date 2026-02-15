import { useEffect, useState, useRef } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Terminal } from "lucide-react";
import { useTranslation } from "react-i18next";

interface UpdateDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function UpdateDialog({ open, onOpenChange }: UpdateDialogProps) {
    const { t } = useTranslation();
    const [logs, setLogs] = useState<string[]>([]);
    const [status, setStatus] = useState<"idle" | "connecting" | "connected" | "error" | "complete">("idle");
    const abortRef = useRef<AbortController | null>(null);
    const bottomRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (open && status === "idle") {
            startUpdate();
        }

        return () => {
            if (abortRef.current) {
                abortRef.current.abort();
                abortRef.current = null;
            }
        };
    }, [open]);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    useEffect(() => {
        if (status !== "complete") return;
        const timer = window.setTimeout(() => window.location.reload(), 5000);
        return () => window.clearTimeout(timer);
    }, [status]);

    const startUpdate = async () => {
        try {
            const token = localStorage.getItem("auth_token");
            if (!token) {
                setLogs(prev => [...prev, `❌ ${t('common.error')}: No auth token`]);
                setStatus("error");
                return;
            }
            const res = await fetch("/api/deploy/webhook", {
                method: "POST",
                headers: { "Authorization": `Bearer ${token}` }
            });

            if (!res.ok) {
                setLogs(prev => [...prev, `❌ ${t('common.error')}: ${res.statusText}`]);
                setStatus("error");
                return;
            }

            setLogs(prev => [...prev, `✅ ${t('update.success_trigger')}`]);
            setStatus("connecting");

            const controller = new AbortController();
            abortRef.current = controller;

            const streamResp = await fetch("/api/deploy/logs", {
                headers: { "Authorization": `Bearer ${token}` },
                signal: controller.signal,
            });

            if (!streamResp.ok || !streamResp.body) {
                setLogs(prev => [...prev, `❌ ${t('update.ws_error')}`]);
                setStatus("error");
                return;
            }

            setStatus("connected");
            setLogs(prev => [...prev, `📡 ${t('update.ws_connected')}`]);

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

                    setLogs(prev => [...prev, eventData]);
                    if (eventData.includes("Update complete!")) {
                        setStatus("complete");
                        controller.abort();
                        return;
                    }
                }
            }

            setLogs(prev => [...prev, `🔌 ${t('update.ws_closed')}`]);

        } catch (e: any) {
            if (e?.name === "AbortError") return;
            setLogs(prev => [...prev, `❌ Exception: ${e.message}`]);
            setStatus("error");
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
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
