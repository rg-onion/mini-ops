import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Shield, History, Plus, Trash2, CheckCircle, XCircle } from "lucide-react";
import { apiFetch } from "@/api";
import { toast } from "sonner";
import { useState } from "react";
import { useTranslation } from "react-i18next";

interface SshLog {
    id: number;
    user: string;
    ip: string;
    timestamp: number;
    method: string;
    notified: boolean;
}

interface TrustedIp {
    id: number;
    ip: string;
    description: string;
    added_at: number;
}

type PendingSshAction =
    | { type: "setup" }
    | { type: "delete"; id: number; ip: string };

async function ensureOk(response: Response) {
    if (response.ok) return response;

    throw new Error((await response.text()) || response.statusText || `HTTP ${response.status}`);
}

export default function SshManagement() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const [newIp, setNewIp] = useState("");
    const [newDesc, setNewDesc] = useState("");
    const [pendingAction, setPendingAction] = useState<PendingSshAction | null>(null);

    const { data: logs } = useQuery<SshLog[]>({
        queryKey: ["ssh-logs"],
        queryFn: () => apiFetch("/ssh/logs").then(r => r.json()),
        refetchInterval: 10000,
    });

    const { data: trustedIps } = useQuery<TrustedIp[]>({
        queryKey: ["trusted-ips"],
        queryFn: () => apiFetch("/ssh/trusted-ips").then(r => r.json()),
    });

    const addIpMutation = useMutation({
        mutationFn: (data: { ip: string, description: string }) =>
            apiFetch("/ssh/trusted-ips", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            }).then(ensureOk),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["trusted-ips"] });
            setNewIp("");
            setNewDesc("");
            toast.success(t('ssh.trusted.added'));
        },
        onError: (error) => toast.error(t('ssh.trusted.add_error', { error: error.message })),
    });

    const deleteIpMutation = useMutation({
        mutationFn: (id: number) => apiFetch(`/ssh/trusted-ips/${id}`, { method: "DELETE" }).then(ensureOk),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["trusted-ips"] });
            toast.success(t('ssh.trusted.deleted'));
        },
        onError: (error) => toast.error(t('ssh.trusted.delete_error', { error: error.message })),
    });

    const setupMutation = useMutation({
        mutationFn: () => apiFetch("/ssh/setup-alerts", { method: "POST" }).then(ensureOk),
        onSuccess: () => toast.success(t('ssh.setup.success')),
        onError: (error) => toast.error(t('ssh.setup.error', { error: error.message })),
    });

    const confirmPendingAction = () => {
        if (!pendingAction) return;

        if (pendingAction.type === "setup") {
            setupMutation.mutate();
        } else {
            deleteIpMutation.mutate(pendingAction.id);
        }

        setPendingAction(null);
    };

    const isConfirmPending = setupMutation.isPending || deleteIpMutation.isPending;

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <h1 className="text-2xl font-bold tracking-tight md:text-3xl">{t('ssh.title')}</h1>
                <Button
                    onClick={() => setPendingAction({ type: "setup" })}
                    disabled={setupMutation.isPending}
                    className="self-start sm:self-auto"
                >
                    <Shield className="mr-2 h-4 w-4" />
                    {t('ssh.setup.btn')}
                </Button>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Shield className="h-5 w-5" />
                            {t('ssh.trusted.title')}
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="flex gap-2 mb-4">
                            <Input placeholder={t('ssh.trusted.ip_placeholder')} value={newIp} onChange={e => setNewIp(e.target.value)} />
                            <Input placeholder={t('ssh.trusted.description_placeholder')} value={newDesc} onChange={e => setNewDesc(e.target.value)} />
                            <Button
                                size="icon"
                                onClick={() => addIpMutation.mutate({ ip: newIp.trim(), description: newDesc.trim() })}
                                disabled={!newIp.trim() || addIpMutation.isPending}
                                title={t('ssh.trusted.add')}
                            >
                                <Plus className="h-4 w-4" />
                            </Button>
                        </div>
                        <div className="rounded-md border overflow-x-auto">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>{t('ssh.trusted.ip')}</TableHead>
                                        <TableHead>{t('ssh.trusted.description')}</TableHead>
                                        <TableHead className="w-[50px]">
                                            <span className="sr-only">{t('containers.actions')}</span>
                                        </TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {trustedIps?.map(ip => (
                                        <TableRow key={ip.id}>
                                            <TableCell className="font-mono text-xs">{ip.ip}</TableCell>
                                            <TableCell className="text-xs text-muted-foreground">{ip.description}</TableCell>
                                            <TableCell>
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    className="h-8 w-8 text-destructive"
                                                    onClick={() => setPendingAction({ type: "delete", id: ip.id, ip: ip.ip })}
                                                    title={t('ssh.trusted.delete')}
                                                >
                                                    <Trash2 className="h-3.5 w-3.5" />
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <History className="h-5 w-5" />
                            {t('ssh.logs.title')}
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="rounded-md border max-h-[400px] overflow-auto">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead className="text-xs">{t('ssh.table.time')}</TableHead>
                                        <TableHead className="text-xs">{t('ssh.table.user')}</TableHead>
                                        <TableHead className="text-xs">{t('ssh.trusted.ip')}</TableHead>
                                        <TableHead className="text-xs">{t('ssh.table.status')}</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {logs?.map(log => (
                                        <TableRow key={log.id}>
                                            <TableCell className="text-[10px] whitespace-nowrap">
                                                {new Date(log.timestamp * 1000).toLocaleString()}
                                            </TableCell>
                                            <TableCell className="text-xs font-medium">{log.user}</TableCell>
                                            <TableCell className="text-[10px] font-mono">{log.ip}</TableCell>
                                            <TableCell>
                                                {log.notified ? (
                                                    <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
                                                ) : (
                                                    <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                                                )}
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    </CardContent>
                </Card>
            </div>

            <Dialog open={!!pendingAction} onOpenChange={(open) => !open && setPendingAction(null)}>
                {pendingAction && (
                    <DialogContent>
                        <DialogHeader>
                            <DialogTitle>
                                {pendingAction.type === "setup"
                                    ? t('ssh.setup.confirm_title')
                                    : t('ssh.trusted.confirm_delete_title')}
                            </DialogTitle>
                            <DialogDescription>
                                {pendingAction.type === "setup"
                                    ? t('ssh.setup.confirm_description')
                                    : t('ssh.trusted.confirm_delete_description', { ip: pendingAction.ip })}
                            </DialogDescription>
                        </DialogHeader>
                        <DialogFooter>
                            <Button variant="outline" onClick={() => setPendingAction(null)}>
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant={pendingAction.type === "delete" ? "destructive" : "default"}
                                onClick={confirmPendingAction}
                                disabled={isConfirmPending}
                            >
                                {pendingAction.type === "setup" ? t('ssh.setup.btn') : t('ssh.trusted.delete')}
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                )}
            </Dialog>
        </div>
    );
}
