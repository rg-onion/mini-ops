import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCheck, Clock3, Info, LoaderCircle, RefreshCcw, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { apiFetch } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { decodeSecurityEvent } from "@/lib/securityEventEvidence";
import type { SecurityEvent } from "@/types";

async function fetchSecurityEvents(): Promise<SecurityEvent[]> {
    const response = await apiFetch("/security/events?status=active&limit=20");
    if (!response.ok) throw new Error("security_events_request_failed");
    const payload: unknown = await response.json();
    if (!Array.isArray(payload)) throw new Error("security_events_invalid_response");

    const events = payload.map(decodeSecurityEvent);
    if (events.some(event => event === null)) throw new Error("security_events_invalid_response");
    return events as SecurityEvent[];
}

async function acknowledgeSecurityEvent(id: number) {
    const response = await apiFetch(`/security/events/${id}/ack`, { method: "POST" });
    if (!response.ok) throw new Error("security_event_ack_failed");
}

function formatTimestamp(timestamp: number) {
    if (!timestamp) return "";
    return new Date(timestamp * 1000).toLocaleString();
}

function severityClass(severity: SecurityEvent["severity"]) {
    switch (severity) {
        case "critical":
            return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300";
        case "high":
            return "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300";
        case "medium":
            return "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300";
        case "low":
            return "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300";
        default:
            return "border-muted-foreground/30 text-muted-foreground";
    }
}

function EvidenceSummary({ event }: { event: SecurityEvent }) {
    const { t } = useTranslation();
    const evidence = event.evidence;

    if (evidence.error_code !== null) {
        return <span>{t("security.evidence.unavailable")}</span>;
    }

    switch (evidence.kind) {
        case "audit.check_failed":
        case "audit.check_warning":
            return (
                <span>
                    {t("security.evidence.audit", {
                        checkId: evidence.data.check_id,
                        status: evidence.data.status,
                    })}
                </span>
            );
        case "ssh.untrusted_source_ip":
            return (
                <span>
                    {t("security.evidence.ssh", {
                        ip: evidence.data.ip,
                        method: evidence.data.method,
                    })}
                </span>
            );
        case "notification.delivery_degraded":
            return (
                <span>
                    {t("security.evidence.notification", {
                        liveLimit: evidence.data.live_limit,
                        terminalLimit: evidence.data.terminal_limit,
                    })}
                </span>
            );
        case "file.sensitive_changed":
            return (
                <span>
                    {t("security.evidence.file", {
                        path: evidence.data.logical_path,
                        changes: evidence.data.change_kinds
                            .map(kind => t(`security.evidence.file_change.${kind}`))
                            .join(", "),
                    })}
                </span>
            );
    }
}

export function SecurityEventsCard() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const [pendingAckIds, setPendingAckIds] = useState<Set<number>>(() => new Set());
    const [failedAckIds, setFailedAckIds] = useState<Set<number>>(() => new Set());
    const eventsQuery = useQuery({
        queryKey: ["security-events"],
        queryFn: fetchSecurityEvents,
        refetchInterval: 30000,
    });

    const ackMutation = useMutation({
        mutationFn: acknowledgeSecurityEvent,
        onMutate: id => {
            setPendingAckIds(current => new Set(current).add(id));
            setFailedAckIds(current => {
                const next = new Set(current);
                next.delete(id);
                return next;
            });
        },
        onSuccess: (_data, id) => {
            toast.success(t("security.event_ack_success"));
            queryClient.invalidateQueries({ queryKey: ["security-events"] });
            setFailedAckIds(current => {
                const next = new Set(current);
                next.delete(id);
                return next;
            });
        },
        onError: (_error, id) => {
            toast.error(t("security.event_ack_error"));
            setFailedAckIds(current => new Set(current).add(id));
        },
        onSettled: (_data, _error, id) => {
            setPendingAckIds(current => {
                const next = new Set(current);
                next.delete(id);
                return next;
            });
        },
    });

    return (
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <div className="flex items-center gap-2">
                    <CardTitle className="text-sm font-medium">{t("security.events_title")}</CardTitle>
                    <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                </div>
                <Badge variant="outline">
                    {eventsQuery.isError ? "!" : eventsQuery.data?.length ?? 0}
                </Badge>
            </CardHeader>
            <CardContent>
                {eventsQuery.isLoading ? (
                    <div
                        aria-busy="true"
                        className="flex items-center justify-center gap-2 rounded-md border px-3 py-6 text-sm text-muted-foreground"
                    >
                        <LoaderCircle className="h-4 w-4 animate-spin" />
                        <span>{t("security.events_loading")}</span>
                    </div>
                ) : eventsQuery.isError || !eventsQuery.data ? (
                    <div
                        role="alert"
                        className="flex flex-col items-center justify-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-6 text-center text-sm text-red-700 dark:text-red-300"
                    >
                        <div className="flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4 shrink-0" />
                            <span>{t("security.events_load_error")}</span>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => eventsQuery.refetch()}
                            disabled={eventsQuery.isFetching}
                        >
                            <RefreshCcw className="h-3.5 w-3.5" />
                            {t("common.retry")}
                        </Button>
                    </div>
                ) : eventsQuery.data.length === 0 ? (
                    <div className="rounded-md border px-3 py-6 text-center text-sm text-muted-foreground">
                        {t("security.no_events")}
                    </div>
                ) : (
                    <div className="overflow-x-auto rounded-md border">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>{t("security.event")}</TableHead>
                                    <TableHead className="w-[190px]">{t("security.status")}</TableHead>
                                    <TableHead className="w-[190px]">{t("security.last_seen")}</TableHead>
                                    <TableHead className="w-[190px]"></TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {eventsQuery.data.map(event => {
                                    const ackPending = pendingAckIds.has(event.id);
                                    const ackError = failedAckIds.has(event.id);

                                    return (
                                        <TableRow key={`${event.event_type}:${event.event_key}`}>
                                            <TableCell>
                                                <div className="space-y-1.5">
                                                    <div className="flex flex-wrap items-center gap-1.5">
                                                        <span className="font-medium">{event.title}</span>
                                                        <Badge variant="outline" className={severityClass(event.severity)}>
                                                            {event.severity}
                                                        </Badge>
                                                    </div>
                                                    <div className="text-sm text-muted-foreground">{event.message}</div>
                                                    <div className="font-mono text-xs text-muted-foreground">
                                                        <EvidenceSummary event={event} />
                                                    </div>
                                                    <div className="font-mono text-[11px] text-muted-foreground/80">
                                                        {event.event_type} · {event.event_key}
                                                    </div>
                                                </div>
                                            </TableCell>
                                            <TableCell>
                                                <div className="flex items-center gap-2 whitespace-nowrap">
                                                    {event.status === "open" ? (
                                                        <AlertTriangle className="h-4 w-4 text-red-500" />
                                                    ) : event.status === "acknowledged" ? (
                                                        <Info className="h-4 w-4 text-amber-600 dark:text-amber-300" />
                                                    ) : (
                                                        <CheckCheck className="h-4 w-4 text-emerald-500" />
                                                    )}
                                                    <span
                                                        className={event.status === "acknowledged"
                                                            ? "text-amber-700 dark:text-amber-300"
                                                            : undefined}
                                                    >
                                                        {t(`security.event_status.${event.status}`)}
                                                    </span>
                                                </div>
                                            </TableCell>
                                            <TableCell>
                                                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                                    <Clock3 className="h-4 w-4" />
                                                    <span>{formatTimestamp(event.last_seen)}</span>
                                                </div>
                                            </TableCell>
                                            <TableCell className="text-right">
                                                {event.status === "open" && (
                                                    <div className="space-y-1.5">
                                                        <Button
                                                            variant="outline"
                                                            size="sm"
                                                            onClick={() => {
                                                                if (!pendingAckIds.has(event.id)) ackMutation.mutate(event.id);
                                                            }}
                                                            disabled={ackPending}
                                                        >
                                                            {ackPending ? (
                                                                <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                                                            ) : (
                                                                <CheckCheck className="h-3.5 w-3.5" />
                                                            )}
                                                            {ackPending ? t("security.ack_pending") : t("security.ack")}
                                                        </Button>
                                                        {ackError && (
                                                            <div role="alert" className="text-xs text-destructive">
                                                                {t("security.event_ack_error")}
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </TableCell>
                                        </TableRow>
                                    );
                                })}
                            </TableBody>
                        </Table>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
