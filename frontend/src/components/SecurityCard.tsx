import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldCheck, ShieldAlert, BadgeCheck, XCircle, AlertTriangle, Bell, Shield } from "lucide-react";
import { apiFetch } from "@/api";
import { toast } from "sonner";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

interface SecurityCheck {
    name: string;
    status: "PASS" | "FAIL" | "WARN";
    message: string;
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
        } catch (e) {
            toast.error(t('security.test_error'));
        } finally {
            setSending(false);
        }
    };

    if (isLoading) return null;

    const allPass = checks?.every(c => c.status === "PASS");

    return (
        <Card className="h-full">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
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
                            SSH Setup
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
                <div className="rounded-md border">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead className="w-[50px]">{t('security.status')}</TableHead>
                                <TableHead>{t('security.check')}</TableHead>
                                <TableHead>{t('security.message')}</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {checks?.map((check) => (
                                <TableRow key={check.name}>
                                    <TableCell>
                                        {check.status === "PASS" && <BadgeCheck className="h-5 w-5 text-emerald-500" />}
                                        {check.status === "FAIL" && <XCircle className="h-5 w-5 text-destructive" />}
                                        {check.status === "WARN" && <AlertTriangle className="h-5 w-5 text-amber-500" />}
                                    </TableCell>
                                    <TableCell className="font-medium">{check.name}</TableCell>
                                    <TableCell className="text-muted-foreground">{check.message}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            </CardContent>
        </Card>
    );
}
