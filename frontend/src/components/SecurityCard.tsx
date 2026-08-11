import { useQuery } from "@tanstack/react-query";
import {
    AlertTriangle,
    BadgeCheck,
    Bell,
    CircleHelp,
    LoaderCircle,
    RefreshCcw,
    Shield,
    ShieldAlert,
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
import {
    auditCheckNameKey,
    auditResultKindMatchesStatus,
    classifySecurityResult,
    isAggregateAuditCheck,
} from "@/lib/securityAudit";
import { readAuditMetadata } from "@/lib/securityEventEvidence";
import type { SecurityAuditResultKind } from "@/types";

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
type CoverageView = "full" | "partial" | "unknown";
type ResultView = "no_findings" | "recommendations" | "confirmed_risks" | "unknown";

interface SecurityAuditResult {
    checks: SecurityCheck[];
    collectionStatus: SecurityCollectionStatus;
}

const CHECK_STATUSES = new Set(["PASS", "FAIL", "WARN"]);
const CHECK_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const MACHINE_IDENTIFIER = /^[a-z0-9._-]+$/u;
const UTF8 = new TextEncoder();
const MAX_AUDIT_CHECKS = 64;

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
    const actual = Object.keys(value);
    return actual.length === expected.length
        && expected.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function isBoundedText(value: unknown, maxBytes: number, allowEmpty = false): value is string {
    return typeof value === "string"
        && UTF8.encode(value).length <= maxBytes
        && (allowEmpty || value.trim().length > 0)
        && ![...value].some(character => {
            const codePoint = character.codePointAt(0) ?? 0;
            return codePoint <= 0x08 || (codePoint >= 0x0b && codePoint <= 0x1f)
                || (codePoint >= 0x7f && codePoint <= 0x9f);
        });
}

function isMachineIdentifier(value: unknown, maxBytes: number): value is string {
    return isBoundedText(value, maxBytes) && MACHINE_IDENTIFIER.test(value);
}

function isBoundedStringArray(
    value: unknown,
    maxItems: number,
    maxItemBytes: number,
    maxTotalBytes: number,
    allowEmptyItems = false,
): value is string[] {
    if (!Array.isArray(value) || value.length > maxItems) return false;
    let totalBytes = 0;
    for (const item of value) {
        if (!isBoundedText(item, maxItemBytes, allowEmptyItems)) return false;
        totalBytes += UTF8.encode(item).length;
        if (totalBytes > maxTotalBytes) return false;
    }
    return true;
}

function isSecurityCheck(value: unknown): value is SecurityCheck {
    if (!isRecord(value) || !hasExactKeys(value, [
        "category",
        "evidence",
        "id",
        "message",
        "metadata",
        "name",
        "references",
        "remediation",
        "severity",
        "status",
    ])) return false;

    const metadata = readAuditMetadata(value.metadata);
    return isMachineIdentifier(value.id, 128)
        && isBoundedText(value.name, 512)
        && isMachineIdentifier(value.category, 64)
        && typeof value.severity === "string"
        && CHECK_SEVERITIES.has(value.severity)
        && typeof value.status === "string"
        && CHECK_STATUSES.has(value.status)
        && isBoundedText(value.message, 4096, true)
        && isBoundedStringArray(value.evidence, 128, 4096, 4096)
        && isBoundedText(value.remediation, 4096, true)
        && isBoundedStringArray(value.references, 16, 2048, 16 * 1024)
        && metadata !== null
        && auditResultKindMatchesStatus(value.status as SecurityCheck["status"], metadata);
}

async function fetchSecurityAudit(): Promise<SecurityAuditResult> {
    const response = await apiFetch("/security/audit");
    if (!response.ok) throw new Error("security_audit_request_failed");

    const payload: unknown = await response.json();
    if (
        !Array.isArray(payload)
        || payload.length > MAX_AUDIT_CHECKS
        || !payload.every(isSecurityCheck)
    ) throw new Error("security_audit_invalid_response");

    const checkIds = payload.map(check => check.id);
    if (new Set(checkIds).size !== checkIds.length) {
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

function resultClass(kind: SecurityAuditResultKind) {
    switch (kind) {
        case "finding":
            return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300";
        case "recommendation":
            return "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200";
        case "pass":
            return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
        default:
            return "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300";
    }
}

function CheckStatusIcon({ status }: { status: SecurityCheck["status"] }) {
    const { t } = useTranslation();
    const label = t(`security.check_status.${status}`);
    if (status === "PASS") return <BadgeCheck aria-label={label} className="h-5 w-5 text-emerald-500" />;
    if (status === "FAIL") return <XCircle aria-label={label} className="h-5 w-5 text-destructive" />;
    return <AlertTriangle aria-label={label} className="h-5 w-5 text-amber-500" />;
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

    const checks = auditQuery.data.checks
        .filter(check => !isAggregateAuditCheck(check.id))
        .map(check => ({
            ...check,
            resultKind: classifySecurityResult(check.status, check.metadata),
        }));
    const coverageView: CoverageView = auditQuery.data.collectionStatus === "full"
        ? "full"
        : auditQuery.data.collectionStatus === "degraded"
            ? "partial"
            : "unknown";
    const resultCounts = checks.reduce<Record<SecurityAuditResultKind, number>>((counts, check) => {
        counts[check.resultKind] += 1;
        return counts;
    }, { pass: 0, finding: 0, recommendation: 0, unverified: 0, coverage: 0 });
    const unverifiedCount = checks.filter(check => (
        check.resultKind === "unverified"
        || check.resultKind === "coverage"
        || check.metadata.coverage_status?.[0] === "partial"
    )).length;
    const concreteResultCount = resultCounts.pass + resultCounts.finding + resultCounts.recommendation;
    const resultView: ResultView = concreteResultCount === 0
        ? "unknown"
        : resultCounts.finding > 0
            ? "confirmed_risks"
            : resultCounts.recommendation > 0
                ? "recommendations"
                : "no_findings";
    const hiddenCoverageOnly = coverageView === "partial" && unverifiedCount === 0;
    const coverageTone = coverageView === "full"
        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
        : coverageView === "partial"
            ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200"
            : "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300";
    const resultTone = resultView === "confirmed_risks"
        ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
        : resultView === "recommendations"
            ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200"
            : resultView === "no_findings"
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                : "border-muted-foreground/30 bg-muted/40 text-muted-foreground";

    return (
        <Card className="h-full">
            <CardHeader className="flex flex-col gap-3 pb-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-2">
                    <CardTitle className="text-sm font-medium">{t("security.title")}</CardTitle>
                    <ShieldAlert className={`h-4 w-4 ${resultView === "confirmed_risks"
                        ? "text-destructive"
                        : coverageView === "full" && resultView === "no_findings"
                            ? "text-emerald-500"
                            : "text-amber-500"}`}
                    />
                </div>
                <div className="flex flex-wrap items-center gap-2">
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
            <CardContent className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2">
                    <section className={`rounded-md border px-3 py-3 text-sm ${coverageTone}`}>
                        <div className="flex flex-wrap items-center gap-2 font-medium">
                            {coverageView === "full" ? (
                                <BadgeCheck className="h-4 w-4" />
                            ) : coverageView === "partial" ? (
                                <AlertTriangle className="h-4 w-4" />
                            ) : (
                                <CircleHelp className="h-4 w-4" />
                            )}
                            <span>{t("security.audit_summary.coverage")}</span>
                            <Badge variant="outline" className={coverageTone}>
                                {t(`security.audit_summary.coverage_state.${coverageView}`)}
                            </Badge>
                        </div>
                        <p className="mt-2 opacity-90">
                            {t(hiddenCoverageOnly
                                ? "security.audit_summary.coverage_detail.partial_unknown_count"
                                : `security.audit_summary.coverage_detail.${coverageView}`, {
                                count: unverifiedCount,
                            })}
                        </p>
                    </section>
                    <section className={`rounded-md border px-3 py-3 text-sm ${resultTone}`}>
                        <div className="flex flex-wrap items-center gap-2 font-medium">
                            {resultView === "confirmed_risks" ? (
                                <XCircle className="h-4 w-4" />
                            ) : resultView === "recommendations" ? (
                                <AlertTriangle className="h-4 w-4" />
                            ) : resultView === "no_findings" ? (
                                <BadgeCheck className="h-4 w-4" />
                            ) : (
                                <CircleHelp className="h-4 w-4" />
                            )}
                            <span>{t("security.audit_summary.result")}</span>
                            <Badge variant="outline" className={resultTone}>
                                {t(`security.audit_summary.result_state.${resultView}`)}
                            </Badge>
                        </div>
                        <p className="mt-2 opacity-90">
                            {t(`security.audit_summary.result_detail.${resultView}`, {
                                count: resultView === "confirmed_risks"
                                    ? resultCounts.finding
                                    : resultCounts.recommendation,
                            })}
                        </p>
                    </section>
                </div>

                <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
                    <AuditFact label={t("security.audit_summary.passed")} value={resultCounts.pass} />
                    <AuditFact label={t("security.audit_summary.confirmed_risks")} value={resultCounts.finding} />
                    <AuditFact label={t("security.audit_summary.recommendations")} value={resultCounts.recommendation} />
                    <AuditFact
                        label={t("security.audit_summary.unverified")}
                        value={hiddenCoverageOnly ? "≥1" : unverifiedCount}
                    />
                </dl>

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
                                    <TableHead className="w-[230px]">{t("security.risk")}</TableHead>
                                    <TableHead>{t("security.message")}</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {checks.map(check => {
                                    const checkNameKey = auditCheckNameKey(check.id);
                                    return (
                                        <TableRow
                                            key={check.id}
                                            className={check.status === "FAIL" || check.resultKind === "finding"
                                                ? "bg-red-500/5 hover:bg-red-500/10"
                                                : undefined}
                                        >
                                            <TableCell>
                                                <CheckStatusIcon status={check.status} />
                                            </TableCell>
                                            <TableCell className="font-medium">
                                                {checkNameKey ? t(checkNameKey) : check.name}
                                            </TableCell>
                                            <TableCell>
                                                <div className="flex flex-wrap gap-1.5">
                                                    <Badge variant="outline" className={resultClass(check.resultKind)}>
                                                        {t(`security.result_kind.${check.resultKind}`)}
                                                    </Badge>
                                                    {check.metadata.coverage_status?.[0] === "partial" && (
                                                        <Badge
                                                            variant="outline"
                                                            className="border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200"
                                                        >
                                                            {t("security.audit_summary.coverage_state.partial")}
                                                        </Badge>
                                                    )}
                                                    <Badge variant="outline">
                                                        {t(`security.category.${check.category}`, { defaultValue: check.category })}
                                                    </Badge>
                                                    <Badge variant="outline" className={severityClass(check.severity)}>
                                                        {t(`security.severity.${check.severity}`)}
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

function AuditFact({ label, value }: { label: string; value: number | string }) {
    return (
        <div className="rounded-md border px-3 py-2">
            <dt className="text-xs text-muted-foreground">{label}</dt>
            <dd className="mt-1 font-medium">{value}</dd>
        </div>
    );
}
