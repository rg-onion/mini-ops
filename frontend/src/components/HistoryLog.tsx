import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { AlertTriangle, History, RefreshCcw, RotateCcw } from "lucide-react";
import { Button } from "./ui/button";
import { useTranslation } from "react-i18next";
import { apiFetch } from "@/api";

interface DeploymentRecord {
    id: string;
    timestamp: string;
    action: "update" | "rollback";
    details: string;
    status: "in_progress" | "success" | "failed";
    image_id: string | null;
    container_name: string | null;
}

function isDeploymentRecord(value: unknown): value is DeploymentRecord {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const record = value as Record<string, unknown>;
    return typeof record.id === "string"
        && typeof record.timestamp === "string"
        && Number.isFinite(Date.parse(record.timestamp))
        && (record.action === "update" || record.action === "rollback")
        && typeof record.details === "string"
        && (record.status === "in_progress" || record.status === "success" || record.status === "failed")
        && (record.image_id === null || typeof record.image_id === "string")
        && (record.container_name === null || typeof record.container_name === "string");
}

async function fetchDeploymentHistory(): Promise<DeploymentRecord[]> {
    const response = await apiFetch("/history");
    if (!response.ok) throw new Error("deployment_history_request_failed");
    const payload: unknown = await response.json();
    if (!Array.isArray(payload) || !payload.every(isDeploymentRecord)) {
        throw new Error("deployment_history_invalid_response");
    }
    return payload;
}

export default function HistoryLog() {
    const { t } = useTranslation();
    const historyQuery = useQuery({
        queryKey: ["deployment-history"],
        queryFn: fetchDeploymentHistory,
    });

    if (historyQuery.isLoading) {
        return <div className="p-8 text-center text-muted-foreground">{t("history.loading")}</div>;
    }

    return (
        <div className="space-y-6">
            <h1 className="text-3xl font-bold tracking-tight">{t('history.title')}</h1>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <History className="h-5 w-5" />
                        {t('history.timeline')}
                    </CardTitle>
                </CardHeader>
                <CardContent className="p-0 sm:p-6">
                    {historyQuery.isError || !historyQuery.data ? (
                        <div
                            role="alert"
                            className="m-4 flex flex-col items-center justify-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-4 py-8 text-center text-sm text-red-700 sm:m-0 dark:text-red-300"
                        >
                            <div className="flex items-center gap-2">
                                <AlertTriangle className="h-4 w-4" />
                                <span>{t("history.load_error")}</span>
                            </div>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => historyQuery.refetch()}
                                disabled={historyQuery.isFetching}
                            >
                                <RefreshCcw className="h-3.5 w-3.5" />
                                {t("common.retry")}
                            </Button>
                        </div>
                    ) : (
                    <div className="overflow-x-auto">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>{t('history.date')}</TableHead>
                                <TableHead>{t('history.action')}</TableHead>
                                <TableHead>{t('history.target')}</TableHead>
                                <TableHead>{t('history.status')}</TableHead>
                                <TableHead className="text-right">{t('containers.actions')}</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {historyQuery.data.map((record) => (
                                <TableRow key={record.id}>
                                    <TableCell className="font-mono text-xs">
                                        {new Date(record.timestamp).toLocaleString()}
                                    </TableCell>
                                    <TableCell className="font-medium capitalize">{record.action}</TableCell>
                                    <TableCell>
                                        <div className="flex flex-col">
                                            <span className="font-medium">{record.container_name || "System"}</span>
                                            <span className="text-xs text-muted-foreground truncate max-w-[200px]">
                                                {record.details}
                                            </span>
                                        </div>
                                    </TableCell>
                                    <TableCell>
                                        <Badge variant={record.status === "success" ? "default" : record.status === "failed" ? "destructive" : "secondary"}>
                                            {record.status}
                                        </Badge>
                                    </TableCell>
                                    <TableCell className="text-right">
                                        {record.image_id && (
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                disabled
                                                title={t("history.rollback_unavailable_detail")}
                                            >
                                                <RotateCcw className="mr-2 h-4 w-4" />
                                                {t("history.rollback_unavailable")}
                                            </Button>
                                        )}
                                    </TableCell>
                                </TableRow>
                            ))}
                            {historyQuery.data.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                                        {t('history.no_history')}
                                    </TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                    </Table>
                    </div>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
