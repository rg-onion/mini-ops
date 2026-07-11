import { useRef, useState } from "react";
import { toast } from "sonner";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { AlertTriangle, Box, FileText, LoaderCircle, MoreHorizontal, Play, RefreshCcw, Square } from "lucide-react";
import type { ContainerInfo } from "@/types";
import { LogViewer } from "./LogViewer";
import { apiFetch } from "@/api";
import { useTranslation } from "react-i18next";

type ContainerAction = "start" | "stop" | "restart";
type PendingContainerAction = {
    id: string;
    name: string;
    action: ContainerAction;
};
type ContainerActionState = PendingContainerAction & {
    status: "pending" | "error";
};

function containerActionKey(id: string, action: ContainerAction) {
    return `${id}:${action}`;
}

async function fetchContainers(): Promise<ContainerInfo[]> {
    const res = await apiFetch("/docker/containers");
    if (!res.ok) throw new Error("Failed to fetch containers");
    return res.json();
}

async function containerAction({ id, action }: PendingContainerAction) {
    const response = await apiFetch(`/docker/containers/${id}/${action}`, { method: "POST" });
    if (!response.ok) throw new Error("container_action_failed");
}

export default function ContainerList() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const [selectedLogId, setSelectedLogId] = useState<string | null>(null);
    const [pendingAction, setPendingAction] = useState<PendingContainerAction | null>(null);
    const [actionStates, setActionStates] = useState<Record<string, ContainerActionState>>({});
    const inFlightActionKeys = useRef<Set<string>>(new Set());

    const { data: containers, isLoading, error } = useQuery({
        queryKey: ["containers"],
        queryFn: fetchContainers,
        refetchInterval: 5000,
    });

    const mutation = useMutation({
        mutationFn: containerAction,
        onMutate: variables => {
            const key = containerActionKey(variables.id, variables.action);
            setActionStates(current => ({
                ...current,
                [key]: {
                    ...variables,
                    status: "pending",
                },
            }));
        },
        onSuccess: (_data, variables) => {
            toast.success(t('containers.success_action', { action: t(`containers.${variables.action}`) }));
            queryClient.invalidateQueries({ queryKey: ["containers"] });
            const key = containerActionKey(variables.id, variables.action);
            setActionStates(current => {
                const next = { ...current };
                delete next[key];
                return next;
            });
            setPendingAction(current => current?.id === variables.id && current.action === variables.action
                ? null
                : current);
        },
        onError: (_error, variables) => {
            toast.error(t("containers.action_failed"));
            const key = containerActionKey(variables.id, variables.action);
            setActionStates(current => ({
                ...current,
                [key]: {
                    ...variables,
                    status: "error",
                },
            }));
        },
        onSettled: (_data, _error, variables) => {
            inFlightActionKeys.current.delete(containerActionKey(variables.id, variables.action));
        },
    });

    const requestAction = (container: ContainerInfo, action: ContainerAction) => {
        const key = containerActionKey(container.id, action);
        setActionStates(current => {
            if (current[key]?.status !== "error") return current;
            const next = { ...current };
            delete next[key];
            return next;
        });
        setPendingAction({
            id: container.id,
            name: container.name.replace(/^\//, ''),
            action,
        });
    };

    const confirmAction = () => {
        if (!pendingAction) return;
        const key = containerActionKey(pendingAction.id, pendingAction.action);
        if (inFlightActionKeys.current.has(key)) return;

        inFlightActionKeys.current.add(key);
        mutation.mutate(pendingAction);
    };

    const pendingDialogState = pendingAction
        ? actionStates[containerActionKey(pendingAction.id, pendingAction.action)]?.status
        : undefined;

    if (isLoading) return <div className="p-8">{t('containers.loading')}</div>;
    if (error) return <div className="p-8 text-destructive">{t('containers.error_loading')}</div>;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                    <Box className="h-6 w-6 text-primary" />
                    <h2 className="text-3xl font-bold tracking-tight">{t('containers.title')}</h2>
                </div>
                <Button variant="outline" size="sm" onClick={() => queryClient.invalidateQueries({ queryKey: ["containers"] })}>
                    <RefreshCcw className="mr-2 h-4 w-4" />
                    {t('common.refresh')}
                </Button>
            </div>

            <div className="rounded-md border bg-card text-card-foreground shadow-sm overflow-x-auto">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead className="w-[200px]">{t('containers.name')}</TableHead>
                            <TableHead>{t('containers.image')}</TableHead>
                            <TableHead>{t('containers.state')}</TableHead>
                            <TableHead>{t('containers.ports')}</TableHead>
                            <TableHead className="text-right">{t('containers.actions')}</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {containers?.map((c) => {
                            const containerStates = Object.values(actionStates).filter(state => state.id === c.id);
                            const hasPendingAction = containerStates.some(state => state.status === "pending");

                            return (
                            <TableRow key={c.id}>
                                <TableCell className="font-medium">
                                    <div className="flex flex-col">
                                        <span>{c.name.replace(/^\//, '')}</span>
                                        <span className="text-xs text-muted-foreground font-mono">{c.id.substring(0, 12)}</span>
                                        {containerStates.map(state => (
                                            <span
                                                key={state.action}
                                                role={state.status === "error" ? "alert" : "status"}
                                                className={state.status === "error"
                                                    ? "mt-1 flex items-center gap-1 text-xs text-destructive"
                                                    : "mt-1 flex items-center gap-1 text-xs text-amber-700 dark:text-amber-300"}
                                            >
                                                {state.status === "pending" ? (
                                                    <LoaderCircle className="h-3 w-3 animate-spin" />
                                                ) : (
                                                    <AlertTriangle className="h-3 w-3" />
                                                )}
                                                {state.status === "pending"
                                                    ? t("containers.action_pending", { action: t(`containers.${state.action}`) })
                                                    : t("containers.action_error", { action: t(`containers.${state.action}`) })}
                                            </span>
                                        ))}
                                    </div>
                                </TableCell>
                                <TableCell className="max-w-[200px] truncate" title={c.image}>
                                    <Badge variant="outline" className="font-mono font-normal">
                                        {c.image.split(':')[0].split('/').pop()}
                                        <span className="opacity-50">:{c.image.split(':')[1] || 'latest'}</span>
                                    </Badge>
                                </TableCell>
                                <TableCell>
                                    <div className="flex items-center gap-2">
                                        <Badge className={`uppercase text-[10px] tracking-wider ${c.state === "running" ? "bg-emerald-500 hover:bg-emerald-600 border-transparent" : c.state === "exited" ? "bg-neutral-500" : "bg-amber-500"}`}>
                                            {c.state}
                                        </Badge>
                                        <span className="text-xs text-muted-foreground truncate max-w-[150px]">{c.status}</span>
                                    </div>
                                </TableCell>
                                <TableCell className="text-xs font-mono text-muted-foreground">{c.ports}</TableCell>
                                <TableCell className="text-right">
                                    <div className="flex justify-end items-center gap-1">
                                        <Button
                                            variant="ghost"
                                            size="icon"
                                            className="h-8 w-8 text-muted-foreground hover:text-primary"
                                            onClick={() => setSelectedLogId(c.id)}
                                            title={t('containers.view_logs')}
                                        >
                                            <FileText className="h-4 w-4" />
                                        </Button>
                                        <DropdownMenu>
                                            <DropdownMenuTrigger asChild>
                                                <Button
                                                    variant="ghost"
                                                    className="h-8 w-8 p-0 ring-offset-background outline-none"
                                                    disabled={hasPendingAction}
                                                >
                                                    <span className="sr-only">{t('common.open_menu')}</span>
                                                    <MoreHorizontal className="h-4 w-4" />
                                                </Button>
                                            </DropdownMenuTrigger>
                                            <DropdownMenuContent align="end">
                                                <DropdownMenuLabel>{t('containers.actions')}</DropdownMenuLabel>
                                                {c.state === "running" ? (
                                                    <>
                                                        <DropdownMenuItem onClick={() => requestAction(c, "stop")}>
                                                            <Square className="mr-2 h-4 w-4 text-destructive" /> {t('containers.stop')}
                                                        </DropdownMenuItem>
                                                        <DropdownMenuItem onClick={() => requestAction(c, "restart")}>
                                                            <RefreshCcw className="mr-2 h-4 w-4" /> {t('containers.restart')}
                                                        </DropdownMenuItem>
                                                    </>
                                                ) : (
                                                    <DropdownMenuItem onClick={() => requestAction(c, "start")}>
                                                        <Play className="mr-2 h-4 w-4 text-emerald-500" /> {t('containers.start')}
                                                    </DropdownMenuItem>
                                                )}
                                            </DropdownMenuContent>
                                        </DropdownMenu>
                                    </div>
                                </TableCell>
                            </TableRow>
                            );
                        })}
                    </TableBody>
                </Table>
            </div>

            <Dialog open={!!selectedLogId} onOpenChange={(open) => !open && setSelectedLogId(null)}>
                <DialogContent className="flex flex-col p-0 gap-0 h-[100dvh] rounded-none sm:h-[80vh] sm:max-w-[800px] sm:rounded-lg [&>button]:hidden">
                    <DialogTitle className="sr-only">{t('containers.logs_dialog_title')}</DialogTitle>
                    <DialogDescription className="sr-only">{t('containers.logs_dialog_description')}</DialogDescription>
                    {selectedLogId && <LogViewer containerId={selectedLogId} onClose={() => setSelectedLogId(null)} />}
                </DialogContent>
            </Dialog>

            <Dialog
                open={!!pendingAction}
                onOpenChange={(open) => {
                    if (!open && pendingDialogState !== "pending") setPendingAction(null);
                }}
            >
                {pendingAction && (
                    <DialogContent>
                        <DialogHeader>
                            <DialogTitle>
                                {t('containers.confirm_action_title', { action: t(`containers.${pendingAction.action}`) })}
                            </DialogTitle>
                            <DialogDescription>
                                {t('containers.confirm_action_description', {
                                    action: t(`containers.${pendingAction.action}`),
                                    name: pendingAction.name,
                                })}
                            </DialogDescription>
                        </DialogHeader>
                        {pendingDialogState === "error" && (
                            <div role="alert" className="flex items-center gap-2 text-sm text-destructive">
                                <AlertTriangle className="h-4 w-4" />
                                {t("containers.action_failed")}
                            </div>
                        )}
                        <DialogFooter>
                            <Button
                                variant="outline"
                                onClick={() => setPendingAction(null)}
                                disabled={pendingDialogState === "pending"}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant={pendingAction.action === "start" ? "default" : "destructive"}
                                onClick={confirmAction}
                                disabled={pendingDialogState === "pending"}
                            >
                                {pendingDialogState === "pending" && <LoaderCircle className="h-4 w-4 animate-spin" />}
                                {pendingDialogState === "pending"
                                    ? t("containers.action_pending", { action: t(`containers.${pendingAction.action}`) })
                                    : t('containers.confirm_action_button', {
                                        action: t(`containers.${pendingAction.action}`),
                                    })}
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                )}
            </Dialog>
        </div>
    );
}
