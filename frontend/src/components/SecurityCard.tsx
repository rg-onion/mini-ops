import { useQuery } from "@tanstack/react-query";
import {
    AlertTriangle,
    BadgeCheck,
    Bell,
    LoaderCircle,
    RefreshCcw,
    Shield,
    ShieldAlert,
    ShieldCheck,
    XCircle,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { apiFetch } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface SecurityCheck {
    id: string;
    name: string;
    category: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    status: "PASS" | "FAIL" | "WARN";
    message: string;
    evidence: string[];
    remediation: string;
    references: string[];
    metadata: Record<string, string[]>;
}

type SecurityCollectionStatus = "full" | "degraded" | "unknown";

interface SecurityAuditResult {
    checks: SecurityCheck[];
    collectionStatus: SecurityCollectionStatus;
}

const CHECK_STATUSES = new Set(["PASS", "FAIL", "WARN"]);
const CHECK_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

function isStringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every(item => typeof item === "string");
}

function isStringArrayMap(value: unknown): value is Record<string, string[]> {
    return typeof value === "object"
        && value !== null
        && !Array.isArray(value)
        && Object.values(value).every(isStringArray);
}

function isSecurityCheck(value: unknown): value is SecurityCheck {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const check = value as Record<string, unknown>;
    return typeof check.id === "string"
        && typeof check.name === "string"
        && typeof check.category === "string"
        && typeof check.severity === "string"
        && CHECK_SEVERITIES.has(check.severity)
        && typeof check.status === "string"
        && CHECK_STATUSES.has(check.status)
        && typeof check.message === "string"
        && isStringArray(check.evidence)
        && typeof check.remediation === "string"
        && isStringArray(check.references)
        && isStringArrayMap(check.metadata);
}

async function fetchSecurityAudit(): Promise<SecurityAuditResult> {
    const response = await apiFetch("/security/audit");
    if (!response.ok) throw new Error("security_audit_request_failed");

    const payload: unknown = await response.json();
    if (!Array.isArray(payload) || !payload.every(isSecurityCheck)) {
        throw new Error("security_audit_invalid_response");
    }
    const checkIds = payload.map(check => check.id);
    if (checkIds.some(id => id.length === 0) || new Set(checkIds).size !== checkIds.length) {
        throw new Error("security_audit_invalid_response");
    }

    const statusHeader = response.headers.get("x-security-collection-status");
    const collectionStatus: SecurityCollectionStatus = statusHeader === "full" || statusHeader === "degraded"
        ? statusHeader
        : "unknown";

    return { checks: payload, collectionStatus };
}

function severityClass(severity: SecurityCheck["severity"]) {
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

export function SecurityCard() {
    const { t } = useTranslation();
    const [sending, setSending] = useState(false);
    const auditQuery = useQuery({
        queryKey: ["security-audit"],
        queryFn: fetchSecurityAudit,
        refetchInterval: 30000,
    });

    const handleTestAlert = async () => {
        setSending(true);
        try {
            const response = await apiFetch("/test-notification", { method: "POST" });
            if (response.ok) {
                toast.success(t("security.test_sent"));
            } else {
                toast.error(t("security.test_fail"));
            }
        } catch {
            toast.error(t("security.test_error"));
        } finally {
            setSending(false);
        }
    };

    if (auditQuery.isLoading) {
        return (
            <Card className="h-full" aria-busy="true">
                <CardHeader>
                    <CardTitle className="text-sm font-medium">{t("security.title")}</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="flex items-center justify-center gap-2 rounded-md border px-3 py-8 text-sm text-muted-foreground">
                        <LoaderCircle className="h-4 w-4 animate-spin" />
                        <span>{t("security.audit_loading")}</span>
                    </div>
                </CardContent>
            </Card>
        );
    }

    if (auditQuery.isError || !auditQuery.data) {
        return (
            <Card className="h-full">
                <CardHeader>
                    <CardTitle className="text-sm font-medium">{t("security.title")}</CardTitle>
                </CardHeader>
                <CardContent>
                    <div
                        role="alert"
                        className="flex flex-col items-center justify-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-8 text-center text-sm text-red-700 dark:text-red-300"
                    >
                        <div className="flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4" />
                            <span>{t("security.audit_load_error")}</span>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => auditQuery.refetch()}
                            disabled={auditQuery.isFetching}
                        >
                            <RefreshCcw className="h-3.5 w-3.5" />
                            {t("common.retry")}
                        </Button>
                    </div>
                </CardContent>
            </Card>
        );
    }

    const { checks, collectionStatus } = auditQuery.data;
    const healthy = collectionStatus === "full"
        && checks.length > 0
        && checks.every(check => check.status === "PASS");
    const hasFindings = collectionStatus === "full"
        && checks.length > 0
        && checks.some(check => check.status !== "PASS");
    const hasConcreteFailure = checks.some(check => check.status === "FAIL");
    const viewStatus = healthy
        ? "healthy"
        : hasFindings
            ? "findings"
            : collectionStatus === "degraded"
                ? "degraded"
                : "unknown";

    const statusClass = viewStatus === "healthy"
        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
        : viewStatus === "findings"
            ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
            : "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200";

    return (
        <Card className="h-full">
            <CardHeader className="flex flex-col gap-3 pb-2 sm:flex-row sm:items-center sm:justify-between sm:gap-0 sm:space-y-0">
                <div className="flex items-center gap-2">
                    <CardTitle className="text-sm font-medium">{t("security.title")}</CardTitle>
                    {healthy ? (
                        <ShieldCheck className="h-4 w-4 text-emerald-500" />
                    ) : hasFindings || hasConcreteFailure ? (
                        <ShieldAlert className="h-4 w-4 text-destructive" />
                    ) : (
                        <AlertTriangle className="h-4 w-4 text-amber-500" />
                    )}
                    <Badge variant="outline" className={statusClass}>
                        {t(`security.audit_state.${viewStatus}`)}
                    </Badge>
                </div>
                <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" className="h-8 gap-1" asChild>
                        <Link to="/ssh">
                            <Shield className="h-3.5 w-3.5" />
                            {t("ssh.setup.btn")}
                        </Link>
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        className="h-8 gap-1"
                        onClick={handleTestAlert}
                        disabled={sending}
                    >
                        <Bell className="h-3.5 w-3.5" />
                        {sending ? t("security.test_sending") : t("security.test_alert")}
                    </Button>
                </div>
            </CardHeader>
            <CardContent className="space-y-3">
                {!healthy && !hasFindings && (
                    <div role="status" className={`rounded-md border px-3 py-3 text-sm ${statusClass}`}>
                        {viewStatus === "degraded"
                            ? t("security.audit_degraded_detail")
                            : t("security.audit_unknown_detail")}
                    </div>
                )}

                {checks.length === 0 ? (
                    <div className="rounded-md border px-3 py-8 text-center text-sm text-muted-foreground">
                        {t("security.audit_no_data")}
                    </div>
                ) : (
                    <div className="overflow-x-auto rounded-md border">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead className="w-[50px]">{t("security.status")}</TableHead>
                                    <TableHead>{t("security.check")}</TableHead>
                                    <TableHead className="w-[180px]">{t("security.risk")}</TableHead>
                                    <TableHead>{t("security.message")}</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {checks.map(check => (
                                    <TableRow key={check.id}>
                                        <TableCell>
                                            {check.status === "PASS" && <BadgeCheck className="h-5 w-5 text-emerald-500" />}
                                            {check.status === "FAIL" && <XCircle className="h-5 w-5 text-destructive" />}
                                            {check.status === "WARN" && <AlertTriangle className="h-5 w-5 text-amber-500" />}
                                        </TableCell>
                                        <TableCell className="font-medium">{check.name}</TableCell>
                                        <TableCell>
                                            <div className="flex flex-wrap gap-1.5">
                                                <Badge variant="outline" className="capitalize">
                                                    {check.category}
                                                </Badge>
                                                <Badge variant="outline" className={severityClass(check.severity)}>
                                                    {check.severity}
                                                </Badge>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <div className="space-y-1.5">
                                                <div className="text-muted-foreground">{check.message}</div>
                                                {check.evidence.length > 0 && (
                                                    <div className="font-mono text-xs text-muted-foreground">
                                                        {check.evidence.slice(0, 3).join(" · ")}
                                                        {check.evidence.length > 3 ? " · ..." : ""}
                                                    </div>
                                                )}
                                                {check.remediation && check.status !== "PASS" && (
                                                    <div className="text-xs text-foreground">{check.remediation}</div>
                                                )}
                                            </div>
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
