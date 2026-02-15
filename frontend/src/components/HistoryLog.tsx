import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Badge } from "./ui/badge";
import { History, RotateCcw } from "lucide-react";
import { Button } from "./ui/button";
import { useTranslation } from "react-i18next";

interface DeploymentRecord {
    id: string;
    timestamp: string;
    action: string;
    details: string;
    status: string;
    image_id?: string;
    container_name?: string;
}

export default function HistoryLog() {
    const { t } = useTranslation();
    const { data: history, isLoading } = useQuery<DeploymentRecord[]>({
        queryKey: ["history"],
        queryFn: async () => {
            const token = localStorage.getItem("auth_token");
            const res = await fetch("/api/history", {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (!res.ok) throw new Error(t('common.error'));
            return res.json();
        }
    });

    if (isLoading) return <div className="p-8 text-center text-muted-foreground">{t('history.loading')}</div>;

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
                <CardContent>
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
                            {history?.map((record) => (
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
                                            <Button variant="ghost" size="sm" onClick={() => alert(t('history.rollback_wip'))}>
                                                <RotateCcw className="mr-2 h-4 w-4" />
                                                {t('history.rollback')}
                                            </Button>
                                        )}
                                    </TableCell>
                                </TableRow>
                            ))}
                            {!history?.length && (
                                <TableRow>
                                    <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                                        {t('history.no_history')}
                                    </TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    );
}
