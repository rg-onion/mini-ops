import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    AlertTriangle,
    BadgeCheck,
    Clock3,
    KeyRound,
    LoaderCircle,
    RefreshCcw,
    ShieldOff,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { apiFetch } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
    decodeCertificateMonitorStatus,
    decodeCertificateRefreshError,
    decodeCertificateRefreshResult,
    readBoundedCertificateJson,
} from "@/lib/certificates";
import type {
    CertificateCurrentObservation,
    CertificateExpiry,
    CertificateMonitorStatus,
    CertificateRefreshErrorCode,
    CertificateRefreshResult,
    CertificateTargetStatus,
} from "@/types";

const CERTIFICATE_QUERY_KEY = ["security-certificates"] as const;
const SECURITY_EVENTS_QUERY_KEY = ["security-events"] as const;

type DisplayErrorCode = CertificateRefreshErrorCode | "invalid_response";

class CertificateRefreshMutationError extends Error {
    readonly code: DisplayErrorCode;
    readonly retryAfterSeconds: number | null;

    constructor(code: DisplayErrorCode, retryAfterSeconds: number | null = null) {
        super(code);
        this.name = "CertificateRefreshMutationError";
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }
}

async function fetchCertificateStatus(): Promise<CertificateMonitorStatus> {
    const response = await apiFetch("/security/certificates");
    if (!response.ok) throw new Error("certificate_status_request_failed");
    const status = decodeCertificateMonitorStatus(await readBoundedCertificateJson(response));
    if (!status) throw new Error("certificate_status_invalid_response");
    return status;
}

function readRetryAfter(response: Response) {
    const value = response.headers.get("retry-after");
    if (value === null || !/^\d+$/.test(value)) return null;
    const seconds = Number(value);
    return Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 3_600 ? seconds : null;
}

async function refreshCertificate(targetId: string): Promise<CertificateRefreshResult> {
    const response = await apiFetch(
        `/security/certificates/${encodeURIComponent(targetId)}/refresh`,
        { method: "POST" },
    );
    let payload: unknown;
    try {
        payload = await readBoundedCertificateJson(response);
    } catch {
        throw new CertificateRefreshMutationError("invalid_response");
    }
    if (!response.ok) {
        const error = decodeCertificateRefreshError(payload);
        throw new CertificateRefreshMutationError(
            error?.error.code ?? "invalid_response",
            readRetryAfter(response),
        );
    }
    const result = decodeCertificateRefreshResult(payload);
    if (!result) throw new CertificateRefreshMutationError("invalid_response");
    return result;
}

function withRefreshedTarget(
    status: CertificateMonitorStatus | undefined,
    result: CertificateRefreshResult,
) {
    if (!status || status.status !== "enabled") return status;
    const targets = status.targets.map(target => (
        target.target_id === result.target.target_id ? result.target : target
    ));
    const expirations = targets
        .map(target => target.observation?.not_after ?? null)
        .filter((expiration): expiration is number => expiration !== null);
    return {
        ...status,
        earliest_expiry_at: expirations.length > 0 ? Math.min(...expirations) : null,
        targets,
    };
}

function formatTimestamp(timestamp: number | null) {
    return timestamp === null ? null : new Date(timestamp * 1000).toLocaleString();
}

function expiryTone(expiry: CertificateExpiry) {
    switch (expiry) {
        case "healthy":
            return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
        case "warning":
            return "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200";
        case "critical":
        case "not_yet_valid":
            return "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300";
        case "expired":
            return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300";
        case "unknown":
            return "border-muted-foreground/30 bg-muted/40 text-muted-foreground";
    }
}

function stateTone(value: string) {
    if (value === "valid" || value === "match") {
        return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
    }
    if (value === "invalid" || value === "mismatch") {
        return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300";
    }
    return "border-muted-foreground/30 bg-muted/40 text-muted-foreground";
}

function remediationKeys(observation: CertificateCurrentObservation | null) {
    if (observation === null) return ["pending"];
    const keys: string[] = [];
    if (observation.error_code !== null
        || observation.reachability === "unknown"
        || observation.trust === "unknown"
        || observation.hostname === "unknown"
        || observation.expiry === "unknown") keys.push("coverage");
    if (observation.trust === "invalid") keys.push("trust");
    if (observation.hostname === "mismatch") keys.push("hostname");
    if (["warning", "critical", "expired", "not_yet_valid"].includes(observation.expiry)) {
        keys.push(`expiry_${observation.expiry}`);
    }
    return keys.length > 0 ? keys : ["healthy"];
}

function formatRemaining(seconds: number, t: ReturnType<typeof useTranslation>["t"]) {
    const absolute = Math.abs(seconds);
    const days = Math.floor(absolute / 86_400);
    const hours = Math.floor((absolute % 86_400) / 3_600);
    const value = days > 0
        ? t("security.certificates.remaining_days", { count: days })
        : absolute < 3_600
            ? t("security.certificates.remaining_less_hour")
            : t("security.certificates.remaining_hours", { count: Math.max(1, hours) });
    return seconds < 0
        ? t("security.certificates.overdue", { value })
        : t("security.certificates.remaining", { value });
}

function formatInterval(seconds: number, t: ReturnType<typeof useTranslation>["t"]) {
    const hours = Math.floor(seconds / 3_600);
    const minutes = Math.floor((seconds % 3_600) / 60);
    if (hours === 0) return t("security.certificates.interval_minutes", { count: minutes });
    if (minutes === 0) return t("security.certificates.interval_hours", { count: hours });
    return t("security.certificates.interval_hours_minutes", { hours, minutes });
}

function formatEndpoint(host: string, port: number) {
    return `${host.includes(":") ? `[${host}]` : host}:${port}`;
}

function ExpiryCell({ observation }: { observation: CertificateCurrentObservation | null }) {
    const { t } = useTranslation();
    if (observation === null) {
        return <span className="text-sm text-muted-foreground">{t("security.certificates.awaiting")}</span>;
    }
    return (
        <div className="space-y-1.5">
            <Badge variant="outline" className={expiryTone(observation.expiry)}>
                {t(`security.certificates.expiry.${observation.expiry}`)}
            </Badge>
            {observation.not_after !== null && (
                <div className="text-xs text-muted-foreground">
                    <div>{formatTimestamp(observation.not_after)}</div>
                    {observation.remaining_seconds !== null && (
                        <div>{formatRemaining(observation.remaining_seconds, t)}</div>
                    )}
                </div>
            )}
        </div>
    );
}

function IdentityCell({ observation }: { observation: CertificateCurrentObservation | null }) {
    const { t } = useTranslation();
    if (observation === null) return <span className="text-sm text-muted-foreground">—</span>;
    return (
        <div className="flex flex-wrap gap-1.5">
            <Badge variant="outline" className={stateTone(observation.hostname)}>
                {t(`security.certificates.hostname.${observation.hostname}`)}
            </Badge>
            <Badge variant="outline" className={stateTone(observation.trust)}>
                {t(`security.certificates.trust.${observation.trust}`)}
            </Badge>
        </div>
    );
}

function CertificateTargetRow({
    target,
    refreshPending,
    refreshDisabled,
    onRefresh,
}: {
    target: CertificateTargetStatus;
    refreshPending: boolean;
    refreshDisabled: boolean;
    onRefresh: () => void;
}) {
    const { t } = useTranslation();
    const observation = target.observation;
    const checkedAt = formatTimestamp(observation?.checked_at ?? null);
    const connectEndpoint = formatEndpoint(target.connect_host, target.port);
    const tlsEndpoint = formatEndpoint(target.server_name, target.port);

    return (
        <TableRow>
            <TableCell className="min-w-[190px] align-top lg:min-w-[230px]">
                <div className="font-medium">{target.label}</div>
                <div className="mt-1 font-mono text-xs text-muted-foreground">{tlsEndpoint}</div>
                {target.connect_host !== target.server_name && (
                    <div className="font-mono text-[11px] text-muted-foreground/80">
                        {t("security.certificates.connect_via", { endpoint: connectEndpoint })}
                    </div>
                )}
                <div className="mt-1 font-mono text-[11px] text-muted-foreground/80">{target.target_id}</div>
            </TableCell>
            <TableCell className="min-w-[170px] align-top"><ExpiryCell observation={observation} /></TableCell>
            <TableCell className="min-w-[190px] align-top"><IdentityCell observation={observation} /></TableCell>
            <TableCell className="min-w-[190px] align-top text-sm">
                <div>{checkedAt ?? t("security.certificates.not_checked")}</div>
                {observation?.last_success_at !== null && observation?.last_success_at !== undefined && (
                    <div className="mt-1 text-xs text-muted-foreground">
                        {t("security.certificates.last_success", {
                            timestamp: formatTimestamp(observation.last_success_at),
                        })}
                    </div>
                )}
                {observation?.error_code && (
                    <div className="mt-1 font-mono text-xs text-amber-700 dark:text-amber-300">
                        {t(`security.certificates.error_code.${observation.error_code}`)}
                    </div>
                )}
            </TableCell>
            <TableCell className="min-w-[230px] align-top text-sm">
                <ul className="space-y-1 text-muted-foreground">
                    {remediationKeys(observation).map(key => (
                        <li key={key}>{t(`security.certificates.remediation.${key}`)}</li>
                    ))}
                </ul>
            </TableCell>
            <TableCell className="w-[130px] align-top text-right">
                <Button
                    variant="outline"
                    size="sm"
                    onClick={onRefresh}
                    disabled={refreshDisabled}
                    aria-label={t("security.certificates.refresh_target", { label: target.label })}
                >
                    {refreshPending ? (
                        <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                        <RefreshCcw className="h-3.5 w-3.5" />
                    )}
                    {t("security.certificates.refresh")}
                </Button>
            </TableCell>
        </TableRow>
    );
}

export function CertificateMonitoringCard() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const statusQuery = useQuery({
        queryKey: CERTIFICATE_QUERY_KEY,
        queryFn: fetchCertificateStatus,
        refetchInterval: 30_000,
    });
    const refreshMutation = useMutation({
        mutationFn: refreshCertificate,
        onSuccess: result => {
            queryClient.setQueryData<CertificateMonitorStatus>(
                CERTIFICATE_QUERY_KEY,
                current => withRefreshedTarget(current, result),
            );
            void queryClient.invalidateQueries({ queryKey: SECURITY_EVENTS_QUERY_KEY });
            toast.success(t("security.certificates.refresh_success", { label: result.target.label }));
        },
        onError: error => {
            const mutationError = error instanceof CertificateRefreshMutationError
                ? error
                : new CertificateRefreshMutationError("invalid_response");
            toast.error(t(`security.certificates.refresh_error.${mutationError.code}`, {
                seconds: mutationError.retryAfterSeconds ?? 60,
            }));
            void queryClient.invalidateQueries({ queryKey: CERTIFICATE_QUERY_KEY });
        },
    });

    const status = statusQuery.data;
    const earliestRemaining = status?.targets.find(
        target => target.observation?.not_after === status.earliest_expiry_at,
    )?.observation?.remaining_seconds ?? null;

    return (
        <Card>
            <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0 pb-3">
                <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                        <CardTitle className="text-sm font-medium">{t("security.certificates.title")}</CardTitle>
                        <KeyRound className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <CardDescription>{t("security.certificates.description")}</CardDescription>
                </div>
                <Badge variant="outline">
                    {statusQuery.isError
                        ? "!"
                        : status
                            ? t(`security.certificates.status.${status.status}`)
                            : "…"}
                </Badge>
            </CardHeader>
            <CardContent>
                {statusQuery.isLoading ? (
                    <div aria-busy="true" className="flex items-center justify-center gap-2 rounded-md border px-3 py-6 text-sm text-muted-foreground">
                        <LoaderCircle className="h-4 w-4 animate-spin" />
                        <span>{t("security.certificates.loading")}</span>
                    </div>
                ) : statusQuery.isError || !status ? (
                    <div role="alert" className="flex flex-col items-center justify-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-6 text-center text-sm text-red-700 dark:text-red-300">
                        <div className="flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4" />
                            <span>{t("security.certificates.load_error")}</span>
                        </div>
                        <Button variant="outline" size="sm" onClick={() => statusQuery.refetch()} disabled={statusQuery.isFetching}>
                            <RefreshCcw className="h-3.5 w-3.5" />
                            {t("common.retry")}
                        </Button>
                    </div>
                ) : status.status === "disabled" ? (
                    <div className="flex items-start gap-3 rounded-md border bg-muted/30 px-3 py-4 text-sm text-muted-foreground">
                        <ShieldOff className="mt-0.5 h-4 w-4 shrink-0" />
                        <span>{t("security.certificates.disabled")}</span>
                    </div>
                ) : (
                    <div className="space-y-4">
                        <div className="grid gap-3 text-sm sm:grid-cols-3">
                            <div className="rounded-md border px-3 py-3">
                                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                    <Clock3 className="h-3.5 w-3.5" />
                                    {t("security.certificates.earliest_expiry")}
                                </div>
                                <div className="mt-1 font-medium">
                                    {status.earliest_expiry_at === null
                                        ? t("security.certificates.unavailable")
                                        : formatTimestamp(status.earliest_expiry_at)}
                                </div>
                                {earliestRemaining !== null && (
                                    <div className="mt-1 text-xs text-muted-foreground">
                                        {formatRemaining(earliestRemaining, t)}
                                    </div>
                                )}
                            </div>
                            <div className="rounded-md border px-3 py-3">
                                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                    <BadgeCheck className="h-3.5 w-3.5" />
                                    {t("security.certificates.targets")}
                                </div>
                                <div className="mt-1 font-medium">{status.targets.length}</div>
                            </div>
                            <div className="rounded-md border px-3 py-3">
                                <div className="text-xs text-muted-foreground">{t("security.certificates.interval")}</div>
                                <div className="mt-1 font-medium">
                                    {formatInterval(status.interval_seconds ?? 300, t)}
                                </div>
                                <div className="mt-1 text-xs text-muted-foreground">
                                    {t("security.certificates.cooldown", {
                                        seconds: status.refresh_cooldown_seconds,
                                    })}
                                </div>
                            </div>
                        </div>

                        <div className="overflow-x-auto rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead className="min-w-[190px] lg:min-w-[230px]">
                                            {t("security.certificates.target")}
                                        </TableHead>
                                        <TableHead>{t("security.certificates.expiry_title")}</TableHead>
                                        <TableHead>{t("security.certificates.identity")}</TableHead>
                                        <TableHead>{t("security.certificates.last_check")}</TableHead>
                                        <TableHead>{t("security.certificates.remediation_title")}</TableHead>
                                        <TableHead><span className="sr-only">{t("security.certificates.actions")}</span></TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {status.targets.map(target => (
                                        <CertificateTargetRow
                                            key={target.target_id}
                                            target={target}
                                            refreshPending={refreshMutation.isPending
                                                && refreshMutation.variables === target.target_id}
                                            refreshDisabled={refreshMutation.isPending}
                                            onRefresh={() => refreshMutation.mutate(target.target_id)}
                                        />
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
