import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCheck, Clock3, ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { apiFetch } from "@/api";
import type { SecurityEvent } from "@/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

async function fetchSecurityEvents(): Promise<SecurityEvent[]> {
    const res = await apiFetch("/security/events?status=active&limit=20");
    if (!res.ok) throw new Error("Failed to fetch security events");
    return res.json();
}

async function acknowledgeSecurityEvent(id: number) {
    const res = await apiFetch(`/security/events/${id}/ack`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to acknowledge security event");
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

export function SecurityEventsCard() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const { data: events, isLoading } = useQuery({
        queryKey: ["security-events"],
        queryFn: fetchSecurityEvents,
        refetchInterval: 30000,
    });

    const ackMutation = useMutation({
        mutationFn: acknowledgeSecurityEvent,
        onSuccess: () => {
            toast.success(t("security.event_ack_success"));
            queryClient.invalidateQueries({ queryKey: ["security-events"] });
        },
        onError: () => toast.error(t("security.event_ack_error")),
    });

    if (isLoading) return null;

    return (
        <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <div className="flex items-center gap-2">
                    <CardTitle className="text-sm font-medium">{t("security.events_title")}</CardTitle>
                    <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                </div>
                <Badge variant="outline">{events?.length || 0}</Badge>
            </CardHeader>
            <CardContent>
                {!events?.length ? (
                    <div className="rounded-md border px-3 py-6 text-center text-sm text-muted-foreground">
                        {t("security.no_events")}
                    </div>
                ) : (
                    <div className="rounded-md border overflow-x-auto">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>{t("security.event")}</TableHead>
                                    <TableHead className="w-[150px]">{t("security.status")}</TableHead>
                                    <TableHead className="w-[190px]">{t("security.last_seen")}</TableHead>
                                    <TableHead className="w-[120px]"></TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {events.map((event) => (
                                    <TableRow key={event.id}>
                                        <TableCell>
                                            <div className="space-y-1.5">
                                                <div className="flex flex-wrap items-center gap-1.5">
                                                    <span className="font-medium">{event.title}</span>
                                                    <Badge variant="outline" className={severityClass(event.severity)}>
                                                        {event.severity}
                                                    </Badge>
                                                </div>
                                                <div className="text-sm text-muted-foreground">{event.message}</div>
                                                <div className="font-mono text-xs text-muted-foreground">{event.event_type}</div>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <div className="flex items-center gap-2">
                                                {event.status === "open" ? (
                                                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                                                ) : (
                                                    <CheckCheck className="h-4 w-4 text-emerald-500" />
                                                )}
                                                <span>{t(`security.event_status.${event.status}`)}</span>
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
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    onClick={() => ackMutation.mutate(event.id)}
                                                    disabled={ackMutation.isPending}
                                                >
                                                    <CheckCheck className="h-3.5 w-3.5" />
                                                    {t("security.ack")}
                                                </Button>
                                            )}
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
