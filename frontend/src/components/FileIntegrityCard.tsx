import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    AlertTriangle,
    FileCheck2,
    FileWarning,
    LoaderCircle,
    RefreshCcw,
    RotateCcw,
    ShieldOff,
} from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { apiFetch } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import {
    decodeFileIntegrityActionError,
    decodeFileIntegrityReenrollResult,
    decodeFileIntegrityStatus,
    decodeFileIntegrityTrustResult,
    readBoundedFileIntegrityJson,
} from "@/lib/fileIntegrity";
import type {
    FileIntegrityActionErrorCode,
    FileIntegrityReenrollResult,
    FileIntegrityStatus,
    FileIntegrityTrustResult,
} from "@/types";

const FILE_INTEGRITY_QUERY_KEY = ["security-file-integrity"] as const;
const SECURITY_EVENTS_QUERY_KEY = ["security-events"] as const;
const HIGH_RISK_REASONS = new Set([
    "baseline_corrupt",
    "unsupported_algorithm",
    "database_restore_required",
    "internal_error",
]);
const REVIEW_REQUIRED_ERRORS = new Set<FileIntegrityActionErrorCode>([
    "invalid_request",
    "stale_generation",
    "not_initialized",
    "no_drift",
    "observation_not_trustable",
    "feature_disabled",
    "recovery_not_required",
    "unsupported_algorithm",
]);

type PendingIntegrityAction =
    | {
        kind: "trust";
        baselineGeneration: number;
        observedGeneration: number;
    }
    | {
        kind: "reenroll";
        stateRevision: number;
        observedGeneration: number;
    };

type IntegrityActionResult = FileIntegrityTrustResult | FileIntegrityReenrollResult;
type DisplayErrorCode = FileIntegrityActionErrorCode | "invalid_response";

class FileIntegrityMutationError extends Error {
    readonly code: DisplayErrorCode;

    constructor(code: DisplayErrorCode) {
        super(code);
        this.name = "FileIntegrityMutationError";
        this.code = code;
    }
}

async function fetchFileIntegrityStatus(): Promise<FileIntegrityStatus> {
    const response = await apiFetch("/security/file-integrity/status");
    if (!response.ok) throw new Error("file_integrity_status_request_failed");

    const payload = await readBoundedFileIntegrityJson(response);
    const status = decodeFileIntegrityStatus(payload);
    if (!status) throw new Error("file_integrity_status_invalid_response");
    return status;
}

async function runIntegrityAction(action: PendingIntegrityAction): Promise<IntegrityActionResult> {
    const trust = action.kind === "trust";
    const response = await apiFetch(
        trust
            ? "/security/file-integrity/trust-current-state"
            : "/security/file-integrity/re-enroll",
        {
            method: "POST",
            body: JSON.stringify(trust
                ? {
                    expected_baseline_generation: action.baselineGeneration,
                    expected_observed_generation: action.observedGeneration,
                    confirmation: "trust_current_state",
                }
                : {
                    expected_state_revision: action.stateRevision,
                    expected_observed_generation: action.observedGeneration,
                    confirmation: "re_enroll_from_current_observation",
                }),
        },
    );

    let payload: unknown;
    try {
        payload = await readBoundedFileIntegrityJson(response);
    } catch {
        throw new FileIntegrityMutationError("invalid_response");
    }

    if (!response.ok) {
        const error = decodeFileIntegrityActionError(payload);
        throw new FileIntegrityMutationError(error?.error.code ?? "invalid_response");
    }

    const result = trust
        ? decodeFileIntegrityTrustResult(payload)
        : decodeFileIntegrityReenrollResult(payload);
    if (!result) throw new FileIntegrityMutationError("invalid_response");
    return result;
}

function formatTimestamp(timestamp: number | null) {
    return timestamp === null ? null : new Date(timestamp * 1000).toLocaleString();
}

function statusClass(status: FileIntegrityStatus) {
    if (status.status === "healthy") {
        return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
    }
    if (status.status === "drift" || (
        status.status === "degraded"
        && status.degraded_reason !== null
        && HIGH_RISK_REASONS.has(status.degraded_reason)
    )) {
        return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300";
    }
    if (status.status === "disabled") {
        return "border-muted-foreground/30 bg-muted/40 text-muted-foreground";
    }
    return "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200";
}

function StatusIcon({ status }: { status: FileIntegrityStatus }) {
    if (status.status === "disabled") return <ShieldOff className="h-4 w-4 text-muted-foreground" />;
    if (status.status === "initializing") return <LoaderCircle className="h-4 w-4 animate-spin text-amber-500" />;
    if (status.status === "healthy") return <FileCheck2 className="h-4 w-4 text-emerald-500" />;
    if (status.status === "drift") return <FileWarning className="h-4 w-4 text-destructive" />;
    return (
        <AlertTriangle
            className={`h-4 w-4 ${status.degraded_reason && HIGH_RISK_REASONS.has(status.degraded_reason)
                ? "text-destructive"
                : "text-amber-500"}`}
        />
    );
}

function actionErrorCode(error: Error | null): DisplayErrorCode | null {
    return error instanceof FileIntegrityMutationError ? error.code : error ? "invalid_response" : null;
}

function isPartialCoverageWithoutDetectedDrift(status: FileIntegrityStatus): boolean {
    return status.status === "degraded"
        && status.degraded_reason === "coverage_unavailable"
        && status.drift_file_count === 0
        && status.coverage.unavailable_target_count > 0;
}

export function FileIntegrityCard() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const actionInFlightRef = useRef(false);
    const [pendingAction, setPendingAction] = useState<PendingIntegrityAction | null>(null);
    const statusQuery = useQuery({
        queryKey: FILE_INTEGRITY_QUERY_KEY,
        queryFn: fetchFileIntegrityStatus,
        refetchInterval: 30000,
    });
    const actionMutation = useMutation({
        mutationFn: runIntegrityAction,
        onSuccess: result => {
            toast.success(t(result.result === "trusted"
                ? "security.file_integrity.trust.success"
                : "security.file_integrity.reenroll.success"));
            setPendingAction(null);
            void queryClient.invalidateQueries({ queryKey: FILE_INTEGRITY_QUERY_KEY });
            void queryClient.invalidateQueries({ queryKey: SECURITY_EVENTS_QUERY_KEY });
        },
        onError: () => {
            toast.error(t("security.file_integrity.action_error.safe"));
            void queryClient.invalidateQueries({ queryKey: FILE_INTEGRITY_QUERY_KEY });
        },
        onSettled: () => {
            actionInFlightRef.current = false;
        },
    });

    const openTrustDialog = (status: FileIntegrityStatus) => {
        if (
            !status.trust_available
            || status.baseline_generation === null
            || status.baseline_generation < 1
            || status.observed_generation === null
            || status.observed_generation < 1
        ) return;
        actionInFlightRef.current = false;
        actionMutation.reset();
        setPendingAction({
            kind: "trust",
            baselineGeneration: status.baseline_generation,
            observedGeneration: status.observed_generation,
        });
    };

    const openReenrollDialog = (status: FileIntegrityStatus) => {
        if (
            !status.re_enroll_available
            || status.state_revision === null
            || status.observed_generation === null
            || status.observed_generation < 1
        ) return;
        actionInFlightRef.current = false;
        actionMutation.reset();
        setPendingAction({
            kind: "reenroll",
            stateRevision: status.state_revision,
            observedGeneration: status.observed_generation,
        });
    };

    const closeDialog = () => {
        if (actionMutation.isPending) return;
        setPendingAction(null);
        actionMutation.reset();
    };

    const errorCode = actionErrorCode(actionMutation.error);
    const reviewRequired = errorCode !== null
        && errorCode !== "invalid_response"
        && REVIEW_REQUIRED_ERRORS.has(errorCode);

    return (
        <>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <div className="flex items-center gap-2">
                        <CardTitle className="text-sm font-medium">
                            {t("security.file_integrity.title")}
                        </CardTitle>
                        {statusQuery.data ? (
                            <StatusIcon status={statusQuery.data} />
                        ) : (
                            <FileWarning className="h-4 w-4 text-muted-foreground" />
                        )}
                    </div>
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => statusQuery.refetch()}
                        disabled={statusQuery.isFetching}
                    >
                        <RefreshCcw className={`h-3.5 w-3.5 ${statusQuery.isFetching ? "animate-spin" : ""}`} />
                        {t("common.refresh")}
                    </Button>
                </CardHeader>
                <CardContent className="space-y-4">
                    {statusQuery.isLoading ? (
                        <div
                            aria-busy="true"
                            className="flex items-center justify-center gap-2 rounded-md border px-3 py-8 text-sm text-muted-foreground"
                        >
                            <LoaderCircle className="h-4 w-4 animate-spin" />
                            {t("security.file_integrity.loading")}
                        </div>
                    ) : statusQuery.isError || !statusQuery.data ? (
                        <div
                            role="alert"
                            className="flex flex-col items-center justify-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-8 text-center text-sm text-red-700 dark:text-red-300"
                        >
                            <div className="flex items-center gap-2">
                                <AlertTriangle className="h-4 w-4" />
                                {t("security.file_integrity.load_error")}
                            </div>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => statusQuery.refetch()}
                                disabled={statusQuery.isFetching}
                            >
                                <RefreshCcw className="h-3.5 w-3.5" />
                                {t("common.retry")}
                            </Button>
                        </div>
                    ) : (
                        <FileIntegrityStatusContent
                            status={statusQuery.data}
                            onTrust={() => openTrustDialog(statusQuery.data)}
                            onReenroll={() => openReenrollDialog(statusQuery.data)}
                        />
                    )}
                </CardContent>
            </Card>

            <Dialog
                open={pendingAction !== null}
                onOpenChange={open => {
                    if (!open) closeDialog();
                }}
            >
                {pendingAction && (
                    <DialogContent>
                        <DialogHeader>
                            <DialogTitle>
                                {t(pendingAction.kind === "trust"
                                    ? "security.file_integrity.trust.title"
                                    : "security.file_integrity.reenroll.title")}
                            </DialogTitle>
                            <DialogDescription>
                                {pendingAction.kind === "trust"
                                    ? t("security.file_integrity.trust.description", {
                                        baselineGeneration: pendingAction.baselineGeneration,
                                        observedGeneration: pendingAction.observedGeneration,
                                    })
                                    : t("security.file_integrity.reenroll.description", {
                                        stateRevision: pendingAction.stateRevision,
                                        observedGeneration: pendingAction.observedGeneration,
                                    })}
                            </DialogDescription>
                        </DialogHeader>

                        {errorCode && (
                            <div role="alert" className="flex items-start gap-2 text-sm text-destructive">
                                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                                <span>
                                    {t(errorCode === "invalid_response"
                                        ? "security.file_integrity.action_error.safe"
                                        : `security.file_integrity.action_error.${errorCode}`)}
                                </span>
                            </div>
                        )}

                        <DialogFooter>
                            <Button variant="outline" onClick={closeDialog} disabled={actionMutation.isPending}>
                                {t(reviewRequired ? "common.close" : "common.cancel")}
                            </Button>
                            <Button
                                variant={pendingAction.kind === "reenroll" ? "destructive" : "default"}
                                onClick={() => {
                                    if (!actionInFlightRef.current && !actionMutation.isPending && !reviewRequired) {
                                        actionInFlightRef.current = true;
                                        actionMutation.mutate(pendingAction);
                                    }
                                }}
                                disabled={actionMutation.isPending || reviewRequired}
                            >
                                {actionMutation.isPending ? (
                                    <LoaderCircle className="h-4 w-4 animate-spin" />
                                ) : pendingAction.kind === "reenroll" ? (
                                    <RotateCcw className="h-4 w-4" />
                                ) : (
                                    <FileCheck2 className="h-4 w-4" />
                                )}
                                {actionMutation.isPending
                                    ? t("common.pending")
                                    : t(pendingAction.kind === "trust"
                                        ? "security.file_integrity.trust.confirm"
                                        : "security.file_integrity.reenroll.confirm")}
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                )}
            </Dialog>
        </>
    );
}

function FileIntegrityStatusContent({
    status,
    onTrust,
    onReenroll,
}: {
    status: FileIntegrityStatus;
    onTrust: () => void;
    onReenroll: () => void;
}) {
    const { t } = useTranslation();
    const lastScan = formatTimestamp(status.last_scan_at);
    const tone = statusClass(status);
    const partialWithoutDrift = isPartialCoverageWithoutDetectedDrift(status);

    return (
        <div className="space-y-4">
            <div className={`rounded-md border px-3 py-3 text-sm ${tone}`} role="status">
                <div className="flex flex-wrap items-center gap-2">
                    <StatusIcon status={status} />
                    <Badge variant="outline" className={tone}>
                        {t(partialWithoutDrift
                            ? "security.file_integrity.status.partial"
                            : `security.file_integrity.status.${status.status}`)}
                    </Badge>
                    <span>
                        {partialWithoutDrift
                            ? t("security.file_integrity.detail.partial_no_drift", {
                                unavailable: status.coverage.unavailable_target_count,
                            })
                            : t(`security.file_integrity.detail.${status.status}`)}
                    </span>
                </div>
                {status.degraded_reason && !partialWithoutDrift && (
                    <div className="mt-2">
                        {t(`security.file_integrity.reason.${status.degraded_reason}`)}
                    </div>
                )}
            </div>

            {status.status !== "disabled" && status.status !== "initializing" && (
                <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
                    <StatusFact label={t("security.file_integrity.tracked_files")} value={status.tracked_file_count} />
                    <StatusFact label={t("security.file_integrity.drift_files")} value={status.drift_file_count} />
                    <StatusFact
                        label={t("security.file_integrity.unavailable_targets")}
                        value={status.coverage.unavailable_target_count}
                    />
                    <StatusFact
                        label={t("security.file_integrity.baseline_generation")}
                        value={status.baseline_generation ?? t("security.file_integrity.unavailable")}
                    />
                    <StatusFact
                        label={t("security.file_integrity.observed_generation")}
                        value={status.observed_generation ?? t("security.file_integrity.unavailable")}
                    />
                    <StatusFact
                        label={t("security.file_integrity.last_scan")}
                        value={lastScan ?? t("security.file_integrity.not_scanned")}
                    />
                </dl>
            )}

            {status.coverage.error_counts.length > 0 && (
                <div className="rounded-md border px-3 py-3 text-sm">
                    <div className="mb-2 font-medium">{t("security.file_integrity.coverage_issues")}</div>
                    <ul className="space-y-1 text-muted-foreground">
                        {status.coverage.error_counts.map(item => (
                            <li key={item.code} className="flex justify-between gap-4">
                                <span>{t(`security.file_integrity.coverage_error.${item.code}`)}</span>
                                <span className="font-mono">{item.count}</span>
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {(status.trust_available || status.re_enroll_available) && (
                <div className="flex flex-wrap justify-end gap-2">
                    {status.trust_available && (
                        <Button onClick={onTrust}>
                            <FileCheck2 className="h-4 w-4" />
                            {t("security.file_integrity.trust.button")}
                        </Button>
                    )}
                    {status.re_enroll_available && (
                        <Button variant="destructive" onClick={onReenroll}>
                            <RotateCcw className="h-4 w-4" />
                            {t("security.file_integrity.reenroll.button")}
                        </Button>
                    )}
                </div>
            )}
        </div>
    );
}

function StatusFact({ label, value }: { label: string; value: string | number }) {
    return (
        <div className="rounded-md border px-3 py-2">
            <dt className="text-xs text-muted-foreground">{label}</dt>
            <dd className="mt-1 break-words font-medium">{value}</dd>
        </div>
    );
}
