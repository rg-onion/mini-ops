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
import {
    AlertTriangle,
    CheckCircle,
    History,
    LoaderCircle,
    Plus,
    RefreshCcw,
    Shield,
    Trash2,
    XCircle,
} from "lucide-react";
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
    description: string | null;
    added_at: number;
}

type PendingSshAction =
    | { type: "setup" }
    | { type: "delete"; id: number; ip: string };

function ensureOk(response: Response) {
    if (response.ok) return response;

    throw new Error("ssh_action_failed");
}

function isSshLog(value: unknown): value is SshLog {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const log = value as Record<string, unknown>;
    return typeof log.id === "number"
        && Number.isSafeInteger(log.id)
        && typeof log.user === "string"
        && typeof log.ip === "string"
        && typeof log.timestamp === "number"
        && Number.isSafeInteger(log.timestamp)
        && typeof log.method === "string"
        && typeof log.notified === "boolean";
}

function isTrustedIp(value: unknown): value is TrustedIp {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const ip = value as Record<string, unknown>;
    return typeof ip.id === "number"
        && Number.isSafeInteger(ip.id)
        && typeof ip.ip === "string"
        && (ip.description === null || typeof ip.description === "string")
        && typeof ip.added_at === "number"
        && Number.isSafeInteger(ip.added_at);
}

async function fetchSshLogs(): Promise<SshLog[]> {
    const response = ensureOk(await apiFetch("/ssh/logs"));
    const payload: unknown = await response.json();
    if (!Array.isArray(payload) || !payload.every(isSshLog)) {
        throw new Error("ssh_logs_invalid_response");
    }
    return payload;
}

async function fetchTrustedIps(): Promise<TrustedIp[]> {
    const response = ensureOk(await apiFetch("/ssh/trusted-ips"));
    const payload: unknown = await response.json();
    if (!Array.isArray(payload) || !payload.every(isTrustedIp)) {
        throw new Error("trusted_ips_invalid_response");
    }
    return payload;
}

export default function SshManagement() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const [newIp, setNewIp] = useState("");
    const [newDesc, setNewDesc] = useState("");
    const [pendingAction, setPendingAction] = useState<PendingSshAction | null>(null);
    const [pendingDeleteIds, setPendingDeleteIds] = useState<Set<number>>(() => new Set());
    const [failedDeleteIds, setFailedDeleteIds] = useState<Set<number>>(() => new Set());

    const logsQuery = useQuery({
        queryKey: ["ssh-logs"],
        queryFn: fetchSshLogs,
        refetchInterval: 10000,
    });

    const trustedIpsQuery = useQuery({
        queryKey: ["trusted-ips"],
        queryFn: fetchTrustedIps,
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
        onError: () => toast.error(t("ssh.trusted.add_error_safe")),
    });

    const deleteIpMutation = useMutation({
        mutationFn: (id: number) => apiFetch(`/ssh/trusted-ips/${id}`, { method: "DELETE" }).then(ensureOk),
        onMutate: id => {
            setPendingDeleteIds(current => new Set(current).add(id));
            setFailedDeleteIds(current => {
                const next = new Set(current);
                next.delete(id);
                return next;
            });
        },
        onSuccess: (_data, id) => {
            queryClient.invalidateQueries({ queryKey: ["trusted-ips"] });
            toast.success(t('ssh.trusted.deleted'));
            setFailedDeleteIds(current => {
                const next = new Set(current);
                next.delete(id);
                return next;
            });
            setPendingAction(current => current?.type === "delete" && current.id === id ? null : current);
        },
        onError: (_error, id) => {
            toast.error(t("ssh.trusted.delete_error_safe"));
            setFailedDeleteIds(current => new Set(current).add(id));
        },
        onSettled: (_data, _error, id) => {
            setPendingDeleteIds(current => {
                const next = new Set(current);
                next.delete(id);
                return next;
            });
        },
    });

    const setupMutation = useMutation({
        mutationFn: () => apiFetch("/ssh/setup-alerts", { method: "POST" }).then(ensureOk),
        onSuccess: () => {
            toast.success(t('ssh.setup.success'));
            setPendingAction(current => current?.type === "setup" ? null : current);
        },
        onError: () => toast.error(t("ssh.setup.error_safe")),
    });

    const confirmPendingAction = () => {
        if (!pendingAction) return;

        if (pendingAction.type === "setup") {
            if (setupMutation.isPending) return;
            setupMutation.mutate();
        } else {
            if (pendingDeleteIds.has(pendingAction.id)) return;
            deleteIpMutation.mutate(pendingAction.id);
        }

    };

    const isConfirmPending = pendingAction?.type === "setup"
        ? setupMutation.isPending
        : pendingAction?.type === "delete"
            ? pendingDeleteIds.has(pendingAction.id)
            : false;
    const isConfirmError = pendingAction?.type === "setup"
        ? setupMutation.isError
        : pendingAction?.type === "delete"
            ? failedDeleteIds.has(pendingAction.id)
            : false;

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <h1 className="text-2xl font-bold tracking-tight md:text-3xl">{t('ssh.title')}</h1>
                <Button
                    onClick={() => setPendingAction({ type: "setup" })}
                    disabled={setupMutation.isPending}
                    className="self-start sm:self-auto"
                >
                    {setupMutation.isPending ? (
                        <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                        <Shield className="mr-2 h-4 w-4" />
                    )}
                    {setupMutation.isPending ? t("ssh.setup.pending") : t('ssh.setup.btn')}
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
                                {addIpMutation.isPending ? (
                                    <LoaderCircle className="h-4 w-4 animate-spin" />
                                ) : (
                                    <Plus className="h-4 w-4" />
                                )}
                            </Button>
                        </div>
                        {addIpMutation.isError && (
                            <div role="alert" className="mb-4 flex items-center gap-2 text-sm text-destructive">
                                <AlertTriangle className="h-4 w-4" />
                                {t("ssh.trusted.add_error_safe")}
                            </div>
                        )}
                        {trustedIpsQuery.isError ? (
                            <div
                                role="alert"
                                className="flex flex-col items-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-6 text-sm text-red-700 dark:text-red-300"
                            >
                                <span>{t("ssh.trusted.load_error")}</span>
                                <Button variant="outline" size="sm" onClick={() => trustedIpsQuery.refetch()}>
                                    <RefreshCcw className="h-3.5 w-3.5" />
                                    {t("common.retry")}
                                </Button>
                            </div>
                        ) : trustedIpsQuery.isLoading ? (
                            <div className="rounded-md border px-3 py-6 text-center text-sm text-muted-foreground">
                                {t("common.loading")}
                            </div>
                        ) : (
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
                                    {trustedIpsQuery.data?.map(ip => {
                                        const deletePending = pendingDeleteIds.has(ip.id);
                                        const deleteError = failedDeleteIds.has(ip.id);

                                        return (
                                        <TableRow key={ip.id}>
                                            <TableCell className="font-mono text-xs">
                                                {ip.ip}
                                                {deleteError && (
                                                    <div role="alert" className="mt-1 font-sans text-xs text-destructive">
                                                        {t("ssh.trusted.delete_error_safe")}
                                                    </div>
                                                )}
                                            </TableCell>
                                            <TableCell className="text-xs text-muted-foreground">
                                                {ip.description ?? "—"}
                                            </TableCell>
                                            <TableCell>
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    className="h-8 w-8 text-destructive"
                                                    onClick={() => setPendingAction({ type: "delete", id: ip.id, ip: ip.ip })}
                                                    title={t('ssh.trusted.delete')}
                                                    disabled={deletePending}
                                                >
                                                    {deletePending ? (
                                                        <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                                                    ) : (
                                                        <Trash2 className="h-3.5 w-3.5" />
                                                    )}
                                                </Button>
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

                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <History className="h-5 w-5" />
                            {t('ssh.logs.title')}
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        {logsQuery.isError ? (
                            <div
                                role="alert"
                                className="flex flex-col items-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-6 text-sm text-red-700 dark:text-red-300"
                            >
                                <span>{t("ssh.logs.load_error")}</span>
                                <Button variant="outline" size="sm" onClick={() => logsQuery.refetch()}>
                                    <RefreshCcw className="h-3.5 w-3.5" />
                                    {t("common.retry")}
                                </Button>
                            </div>
                        ) : logsQuery.isLoading ? (
                            <div className="rounded-md border px-3 py-6 text-center text-sm text-muted-foreground">
                                {t("common.loading")}
                            </div>
                        ) : (
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
                                    {logsQuery.data?.map(log => (
                                        <TableRow key={log.id}>
                                            <TableCell className="text-[10px] whitespace-nowrap">
                                                {new Date(log.timestamp * 1000).toLocaleString()}
                                            </TableCell>
                                            <TableCell className="text-xs font-medium">{log.user}</TableCell>
                                            <TableCell className="text-[10px] font-mono">{log.ip}</TableCell>
                                            <TableCell>
                                                <div className="flex items-center gap-1.5 whitespace-nowrap text-xs">
                                                    {log.notified ? (
                                                        <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
                                                    ) : (
                                                        <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                                                    )}
                                                    <span>{log.notified ? t("ssh.table.queued") : t("ssh.table.not_queued")}</span>
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
            </div>

            <Dialog
                open={!!pendingAction}
                onOpenChange={(open) => {
                    if (!open && !isConfirmPending) setPendingAction(null);
                }}
            >
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
                        {isConfirmError && (
                            <div role="alert" className="flex items-center gap-2 text-sm text-destructive">
                                <AlertTriangle className="h-4 w-4" />
                                {pendingAction.type === "setup"
                                    ? t("ssh.setup.error_safe")
                                    : t("ssh.trusted.delete_error_safe")}
                            </div>
                        )}
                        <DialogFooter>
                            <Button variant="outline" onClick={() => setPendingAction(null)} disabled={isConfirmPending}>
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant={pendingAction.type === "delete" ? "destructive" : "default"}
                                onClick={confirmPendingAction}
                                disabled={isConfirmPending}
                            >
                                {isConfirmPending && <LoaderCircle className="h-4 w-4 animate-spin" />}
                                {isConfirmPending
                                    ? t("common.pending")
                                    : pendingAction.type === "setup"
                                        ? t('ssh.setup.btn')
                                        : t('ssh.trusted.delete')}
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                )}
            </Dialog>
        </div>
    );
}
