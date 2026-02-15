import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
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

export default function SshManagement() {
    const { t } = useTranslation();
    const queryClient = useQueryClient();
    const [newIp, setNewIp] = useState("");
    const [newDesc, setNewDesc] = useState("");

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
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["trusted-ips"] });
            setNewIp("");
            setNewDesc("");
            toast.success("IP added to whitelist");
        }
    });

    const deleteIpMutation = useMutation({
        mutationFn: (id: number) => apiFetch(`/ssh/trusted-ips/${id}`, { method: "POST" }),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["trusted-ips"] }),
    });

    const setupMutation = useMutation({
        mutationFn: () => apiFetch("/ssh/setup-alerts", { method: "POST" }),
        onSuccess: () => toast.success(t('ssh.setup.success')),
        onError: () => toast.error(t('ssh.setup.error')),
    });

    return (
        <div className="space-y-6 p-6">
            <div className="flex items-center justify-between">
                <h1 className="text-3xl font-bold tracking-tight">SSH Security</h1>
                <Button onClick={() => setupMutation.mutate()} disabled={setupMutation.isPending}>
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
                            <Input placeholder="IP" value={newIp} onChange={e => setNewIp(e.target.value)} />
                            <Input placeholder="Desc" value={newDesc} onChange={e => setNewDesc(e.target.value)} />
                            <Button size="icon" onClick={() => addIpMutation.mutate({ ip: newIp, description: newDesc })}>
                                <Plus className="h-4 w-4" />
                            </Button>
                        </div>
                        <div className="rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>IP</TableHead>
                                        <TableHead>Desc</TableHead>
                                        <TableHead className="w-[50px]"></TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {trustedIps?.map(ip => (
                                        <TableRow key={ip.id}>
                                            <TableCell className="font-mono text-xs">{ip.ip}</TableCell>
                                            <TableCell className="text-xs text-muted-foreground">{ip.description}</TableCell>
                                            <TableCell>
                                                <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive" onClick={() => deleteIpMutation.mutate(ip.id)}>
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
                                        <TableHead className="text-xs">IP</TableHead>
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
        </div>
    );
}
