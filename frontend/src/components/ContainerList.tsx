import { useState } from "react";
import { toast } from "sonner";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Play, Square, RefreshCcw, FileText, MoreHorizontal, Box } from "lucide-react";
import type { ContainerInfo } from "@/types";
import { LogViewer } from "./LogViewer";
import { apiFetch } from "@/api";
import { useTranslation } from "react-i18next";

async function fetchContainers(): Promise<ContainerInfo[]> {
    const res = await apiFetch("/docker/containers");
    if (!res.ok) throw new Error("Failed to fetch containers");
    return res.json();
}

async function containerAction({ id, action }: { id: string; action: string }) {
    const res = await apiFetch(`/docker/containers/${id}/${action}`, { method: "POST" });
    if (!res.ok) throw new Error(`Failed to ${action} container`);
    return res;
}

export default function ContainerList() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const [selectedLogId, setSelectedLogId] = useState<string | null>(null);

    const { data: containers, isLoading, error } = useQuery({
        queryKey: ["containers"],
        queryFn: fetchContainers,
        refetchInterval: 5000,
    });

    const mutation = useMutation({
        mutationFn: containerAction,
        onSuccess: (_data, variables) => {
            toast.success(t('containers.success_action', { action: variables.action }));
            queryClient.invalidateQueries({ queryKey: ["containers"] });
        },
        onError: (error) => {
            toast.error(t('containers.error_action', { error: error.message }));
        }
    });

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

            <div className="rounded-md border bg-card text-card-foreground shadow-sm">
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
                        {containers?.map((c) => (
                            <TableRow key={c.id}>
                                <TableCell className="font-medium">
                                    <div className="flex flex-col">
                                        <span>{c.name.replace(/^\//, '')}</span>
                                        <span className="text-xs text-muted-foreground font-mono">{c.id.substring(0, 12)}</span>
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
                                                <Button variant="ghost" className="h-8 w-8 p-0 ring-offset-background outline-none">
                                                    <span className="sr-only">Open menu</span>
                                                    <MoreHorizontal className="h-4 w-4" />
                                                </Button>
                                            </DropdownMenuTrigger>
                                            <DropdownMenuContent align="end">
                                                <DropdownMenuLabel>{t('containers.actions')}</DropdownMenuLabel>
                                                {c.state === "running" ? (
                                                    <>
                                                        <DropdownMenuItem onClick={() => mutation.mutate({ id: c.id, action: "stop" })}>
                                                            <Square className="mr-2 h-4 w-4 text-destructive" /> {t('containers.stop')}
                                                        </DropdownMenuItem>
                                                        <DropdownMenuItem onClick={() => mutation.mutate({ id: c.id, action: "restart" })}>
                                                            <RefreshCcw className="mr-2 h-4 w-4" /> {t('containers.restart')}
                                                        </DropdownMenuItem>
                                                    </>
                                                ) : (
                                                    <DropdownMenuItem onClick={() => mutation.mutate({ id: c.id, action: "start" })}>
                                                        <Play className="mr-2 h-4 w-4 text-emerald-500" /> {t('containers.start')}
                                                    </DropdownMenuItem>
                                                )}
                                            </DropdownMenuContent>
                                        </DropdownMenu>
                                    </div>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </div>

            <Dialog open={!!selectedLogId} onOpenChange={(open) => !open && setSelectedLogId(null)}>
                <DialogContent className="sm:max-w-[800px] h-[80vh] flex flex-col p-0 gap-0">
                    <DialogTitle className="sr-only">Container Logs</DialogTitle>
                    <DialogDescription className="sr-only">Real-time logs for the selected container</DialogDescription>
                    {selectedLogId && <LogViewer containerId={selectedLogId} onClose={() => setSelectedLogId(null)} />}
                </DialogContent>
            </Dialog>
        </div>
    );
}
