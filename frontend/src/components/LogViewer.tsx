import { useEffect, useRef, useState, useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useTranslation } from "react-i18next";
import { Pause, Play, Clock, Trash2, X, Download } from "lucide-react";

interface LogViewerProps {
    containerId: string;
    onClose: () => void;
}

export function LogViewer({ containerId, onClose }: LogViewerProps) {
    const { t } = useTranslation();
    const [logs, setLogs] = useState<string[]>([]);
    const [status, setStatus] = useState<"connecting" | "connected" | "error" | "closed">("connecting");
    const [isPaused, setIsPaused] = useState(false);
    const [timeRange, setTimeRange] = useState<{ tail?: string, since?: number, labelKey: string }>({ tail: "1000", labelKey: "last_1000" });
    const [searchTerm, setSearchTerm] = useState("");

    const scrollRef = useRef<HTMLDivElement>(null);
    const abortRef = useRef<AbortController | null>(null);

    useEffect(() => {
        const token = localStorage.getItem("auth_token");

        if (!token) {
            setLogs([`--- ${t('common.error')}: No Auth Token Found ---`]);
            setStatus("error");
            return;
        }

        const params = new URLSearchParams();
        if (timeRange.tail) params.set("tail", timeRange.tail);
        if (timeRange.since) params.set("since", String(timeRange.since));
        const url = `/api/docker/containers/${containerId}/logs?${params.toString()}`;
        const controller = new AbortController();
        abortRef.current = controller;

        const connect = async () => {
            try {
                const response = await fetch(url, {
                    headers: { "Authorization": `Bearer ${token}` },
                    signal: controller.signal,
                });

                if (!response.ok || !response.body) {
                    setStatus("error");
                    setLogs([`--- ${t('common.error')}: ${response.statusText} ---`]);
                    return;
                }

                setStatus("connected");
                setLogs(["--- Log Stream Started (SSE) ---"]);

                const reader = response.body.getReader();
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
                        const payload = normalized.slice(5).trimStart();
                        if (!payload) continue;

                        setLogs((prev: string[]) => {
                            const newLogs = [...prev, payload];
                            return newLogs.length > 10000 ? newLogs.slice(-10000) : newLogs;
                        });
                    }
                }

                setStatus("closed");
                setLogs((prev: string[]) => [...prev, "--- Stream Closed ---"]);
            } catch (e: any) {
                if (e?.name === "AbortError") return;
                setStatus("error");
                setLogs((prev: string[]) => [...prev, `--- ${t('common.error')} (See Console) ---`]);
            }
        };

        connect();

        return () => {
            controller.abort();
        };
    }, [containerId, t, timeRange]);

    const filteredLogs = useMemo(() => {
        if (!searchTerm) return logs;
        const lowerTerm = searchTerm.toLowerCase();
        return logs.filter(log => log.toLowerCase().includes(lowerTerm));
    }, [logs, searchTerm]);

    useEffect(() => {
        if (!isPaused && scrollRef.current && !searchTerm) {
            scrollRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [logs, isPaused, searchTerm]);

    const clearLogs = () => setLogs([]);

    const handleTimeSelect = (labelKey: string, tail?: string, minutes?: number) => {
        setLogs([]);
        if (minutes) {
            const since = Math.floor(Date.now() / 1000) - (minutes * 60);
            setTimeRange({ since, labelKey });
        } else {
            setTimeRange({ tail, labelKey });
        }
    };

    const handleDownload = () => {
        const selection = window.getSelection();
        const selectedText = selection?.toString();
        const textToSave = selectedText || filteredLogs.join("\n");

        if (!textToSave) return;

        const blob = new Blob([textToSave], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;

        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const suffix = selectedText ? "selection" : "full";
        a.download = `logs-${containerId.substring(0, 12)}-${suffix}-${timestamp}.txt`;

        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const toggleFilter = (term: string) => {
        setSearchTerm(prev => prev === term ? "" : term);
    };

    const buttons = [
        { label: "btn_100", tail: "100", labelKey: "last_100" },
        { label: "btn_1k", tail: "1000", labelKey: "last_1000" },
        { label: "btn_15m", minutes: 15, labelKey: "last_15m" },
        { label: "btn_1h", minutes: 60, labelKey: "last_1h" },
        { label: "btn_24h", minutes: 1440, labelKey: "last_24h" },
        { label: "btn_all", tail: "all", labelKey: "last_10000" },
    ];

    return (
        <div className="flex flex-col h-full bg-black text-green-500 font-mono text-xs overflow-hidden">
            <div className="flex flex-col border-b border-white/10 bg-zinc-900 text-white shrink-0 z-10">
                <div className="flex justify-between items-center p-3 pb-2">
                    <div className="flex items-center gap-3">
                        <h3 className="font-semibold flex items-center gap-2">
                            <Clock className="w-4 h-4 text-muted-foreground" />
                            {containerId.substring(0, 12)}
                            <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded ${status === "connected" ? "bg-green-500/20 text-green-500" :
                                status === "error" ? "bg-red-500/20 text-red-500" : "bg-yellow-500/20 text-yellow-500"
                                }`}>
                                {t(`common.status.${status}`)}
                            </span>
                        </h3>

                        <div className="h-4 w-[1px] bg-white/10 mx-1" />

                        <div className="flex bg-white/5 rounded-md p-0.5 gap-0.5">
                            {buttons.map((btn) => (
                                <button
                                    key={btn.labelKey}
                                    onClick={() => handleTimeSelect(btn.labelKey, btn.tail, btn.minutes)}
                                    className={`px-3 py-1.5 text-xs rounded transition-colors ${timeRange.labelKey === btn.labelKey
                                        ? "bg-white/20 text-white font-medium shadow-sm"
                                        : "text-white/50 hover:text-white hover:bg-white/10"
                                        }`}
                                    title={t(`containers.logs_control.${btn.labelKey}`)}
                                >
                                    {t(`containers.logs_control.${btn.label}`)}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1 mr-2">
                            <div className="relative w-40 sm:w-64">
                                <Input
                                    placeholder={t('containers.logs_control.search_placeholder')}
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                    className="h-8 px-3 bg-black/20 border-white/10 text-xs text-white placeholder:text-white/30 focus-visible:ring-1 focus-visible:ring-white/20"
                                />
                            </div>
                            {searchTerm && (
                                <button
                                    onClick={() => setSearchTerm("")}
                                    className="h-8 w-8 flex items-center justify-center text-white/50 hover:text-white hover:bg-white/10 rounded transition-colors"
                                >
                                    <X className="w-3 h-3" />
                                </button>
                            )}
                        </div>

                        <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 gap-2 text-white/70 hover:text-white"
                            onClick={handleDownload}
                            title={t('containers.logs_control.download')}
                        >
                            <Download className="w-4 h-4" />
                            <span className="hidden sm:inline">{t('containers.logs_control.download')}</span>
                        </Button>
                        <Button
                            variant="ghost"
                            size="sm"
                            className={`h-8 gap-2 rounded-md ${isPaused ? "text-amber-500 hover:text-amber-400 bg-amber-500/10" : "text-white/70 hover:text-white"}`}
                            onClick={() => setIsPaused(!isPaused)}
                        >
                            {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                        </Button>
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-white/50 hover:text-red-400" onClick={clearLogs} title={t('containers.logs_control.clear')}>
                            <Trash2 className="w-4 h-4" />
                        </Button>
                        <div className="h-4 w-[1px] bg-white/10 mx-1" />
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-white/50 hover:text-white" onClick={onClose} title={t('common.close')}>
                            <X className="w-4 h-4" />
                        </Button>
                    </div>
                </div>

                <div className="flex items-center gap-2 px-3 pb-2 overflow-x-auto">
                    <span className="text-[10px] text-white/40 uppercase font-medium">Quick Filter:</span>
                    <button
                        onClick={() => toggleFilter("ERROR")}
                        className={`text-xs px-3 py-1 rounded border ${searchTerm === "ERROR"
                            ? "bg-red-500/20 border-red-500/50 text-red-500"
                            : "bg-transparent border-white/10 text-white/50 hover:border-white/30 hover:text-white"
                            }`}
                    >
                        ERROR
                    </button>
                    <button
                        onClick={() => toggleFilter("WARN")}
                        className={`text-xs px-3 py-1 rounded border ${searchTerm === "WARN"
                            ? "bg-yellow-500/20 border-yellow-500/50 text-yellow-500"
                            : "bg-transparent border-white/10 text-white/50 hover:border-white/30 hover:text-white"
                            }`}
                    >
                        WARN
                    </button>
                    <button
                        onClick={() => toggleFilter("INFO")}
                        className={`text-xs px-3 py-1 rounded border ${searchTerm === "INFO"
                            ? "bg-blue-500/20 border-blue-500/50 text-blue-500"
                            : "bg-transparent border-white/10 text-white/50 hover:border-white/30 hover:text-white"
                            }`}
                    >
                        INFO
                    </button>
                    {searchTerm && !["ERROR", "WARN", "INFO"].includes(searchTerm) && (
                        <span className="text-[10px] text-white/70 bg-white/10 px-2 py-0.5 rounded">
                            Searching: "{searchTerm}" ({filteredLogs.length} matches)
                        </span>
                    )}
                </div>
            </div>

            <ScrollArea className="flex-1 p-4 overflow-y-auto">
                <div className="space-y-0.5">
                    {filteredLogs.length > 0 ? (
                        filteredLogs.map((log, index) => (
                            <div key={index} className="whitespace-pre-wrap break-all opacity-90 hover:opacity-100 transition-opacity">
                                {log}
                            </div>
                        ))
                    ) : (
                        <div className="text-white/30 italic text-center py-10">
                            {logs.length > 0 ? "No matches found." : "Waiting for logs..."}
                        </div>
                    )}
                    <div ref={scrollRef} className="h-px" />
                </div>
            </ScrollArea>
        </div>
    );
}
