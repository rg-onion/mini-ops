import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldCheck, ShieldAlert, BadgeCheck, XCircle, AlertTriangle, Bell, Shield } from "lucide-react";
import { apiFetch } from "@/api";
import { toast } from "sonner";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

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

async function fetchSecurityAudit(): Promise<SecurityCheck[]> {
    const res = await apiFetch("/security/audit");
    if (!res.ok) throw new Error("Failed to fetch security audit");
    return res.json();
}

export function SecurityCard() {
    const { t } = useTranslation();
    const [sending, setSending] = useState(false);
    const { data: checks, isLoading } = useQuery({
        queryKey: ["security"],
        queryFn: fetchSecurityAudit,
        refetchInterval: 30000,
    });

    const handleTestAlert = async () => {
        setSending(true);
        try {
            const res = await apiFetch("/test-notification", { method: "POST" });
            if (res.ok) {
                toast.success(t('security.test_sent'));
            } else {
                toast.error(t('security.test_fail'));
            }
        } catch {
            toast.error(t('security.test_error'));
        } finally {
            setSending(false);
        }
    };

    if (isLoading) return null;

    const allPass = checks?.every(c => c.status === "PASS");
    const severityClass = (severity: SecurityCheck["severity"]) => {
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
    };

    return (
        <Card className="h-full">
            <CardHeader className="flex flex-col gap-3 pb-2 sm:flex-row sm:items-center sm:justify-between sm:gap-0 sm:space-y-0">
                <div className="flex items-center gap-2">
                    <CardTitle className="text-sm font-medium">{t('security.title')}</CardTitle>
                    {allPass ? (
                        <ShieldCheck className="h-4 w-4 text-emerald-500" />
                    ) : (
                        <ShieldAlert className="h-4 w-4 text-destructive" />
                    )}
                </div>
                <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" className="h-8 gap-1" asChild>
                        <Link to="/ssh">
                            <Shield className="h-3.5 w-3.5" />
                            {t('ssh.setup.btn')}
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
                        {t('security.test_alert')}
                    </Button>
                </div>
            </CardHeader>
            <CardContent>
                <div className="rounded-md border overflow-x-auto">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead className="w-[50px]">{t('security.status')}</TableHead>
                                <TableHead>{t('security.check')}</TableHead>
                                <TableHead className="w-[180px]">{t('security.risk')}</TableHead>
                                <TableHead>{t('security.message')}</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {checks?.map((check) => (
                                <TableRow key={check.id || check.name}>
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
                                            {check.evidence?.length > 0 && (
                                                <div className="font-mono text-xs text-muted-foreground">
                                                    {check.evidence.slice(0, 3).join(" · ")}
                                                    {check.evidence.length > 3 ? " · ..." : ""}
                                                </div>
                                            )}
                                            {check.remediation && check.status !== "PASS" && (
                                                <div className="text-xs text-foreground">
                                                    {check.remediation}
                                                </div>
                                            )}
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            </CardContent>
        </Card>
    );
}
