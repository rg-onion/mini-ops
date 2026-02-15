import { useEffect, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "./ui/dialog";
import { Button } from "./ui/button";
import { HardDrive, Trash2, RotateCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";

interface DiskUsage {
    target_size: string;
    node_modules_size: string;
    docker_size: string;
    logs_size: string;
}

export function DiskManager() {
    const { t } = useTranslation();
    const [usage, setUsage] = useState<DiskUsage | null>(null);
    const [cleaning, setCleaning] = useState<string | null>(null);

    const fetchUsage = async () => {
        try {
            const token = localStorage.getItem("auth_token");
            const res = await fetch("/api/disk/usage", {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) setUsage(await res.json());
        } finally {
            // done
        }
    };

    const handleClean = async (target: string) => {
        if (!confirm(t('disk.confirm_clean', { target }))) return;

        setCleaning(target);
        try {
            const token = localStorage.getItem("auth_token");
            const res = await fetch("/api/disk/clean", {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ target })
            });

            if (res.ok) {
                toast.success(await res.text());
                fetchUsage();
            } else {
                toast.error(t('common.error') + ": " + await res.text());
            }
        } finally {
            setCleaning(null);
        }
    };

    useEffect(() => {
    }, []);

    return (
        <Dialog onOpenChange={(open) => open && fetchUsage()}>
            <DialogTrigger asChild>
                <button className="w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-muted hover:text-foreground text-left transition-all">
                    <HardDrive className="h-4 w-4" />
                    {t('disk.trigger')}
                </button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[600px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <HardDrive className="h-5 w-5" />
                        {t('disk.title')}
                    </DialogTitle>
                </DialogHeader>

                <div className="grid grid-cols-2 gap-4 mt-4">
                    {/* Rust Artifacts */}
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">{t('disk.rust_build')}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{usage?.target_size || "..."}</div>
                            <Button variant="destructive" size="sm" className="w-full mt-4"
                                onClick={() => handleClean("target")} disabled={!!cleaning}>
                                {cleaning === "target" ? <RotateCw className="animate-spin h-4 w-4" /> : <Trash2 className="h-4 w-4 mr-2" />}
                                {t('disk.clean')}
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Node Modules */}
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">{t('disk.frontend_cache')}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{usage?.node_modules_size || "..."}</div>
                            <Button variant="destructive" size="sm" className="w-full mt-4"
                                onClick={() => handleClean("node_modules")} disabled={!!cleaning}>
                                {cleaning === "node_modules" ? <RotateCw className="animate-spin h-4 w-4" /> : <Trash2 className="h-4 w-4 mr-2" />}
                                {t('disk.clean')}
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Docker */}
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">{t('disk.docker_system')}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{usage?.docker_size || "..."}</div>
                            <p className="text-xs text-muted-foreground mb-4">{t('disk.prune_desc')}</p>
                            <Button variant="destructive" size="sm" className="w-full"
                                onClick={() => handleClean("docker")} disabled={!!cleaning}>
                                {cleaning === "docker" ? <RotateCw className="animate-spin h-4 w-4" /> : <Trash2 className="h-4 w-4 mr-2" />}
                                {t('disk.prune')}
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Logs */}
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">{t('disk.system_logs')}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{usage?.logs_size || "..."}</div>
                            <Button variant="secondary" size="sm" className="w-full mt-4"
                                onClick={() => handleClean("logs")} disabled={!!cleaning}>
                                {cleaning === "logs" ? <RotateCw className="animate-spin h-4 w-4" /> : <Trash2 className="h-4 w-4 mr-2" />}
                                {t('disk.vacuum')}
                            </Button>
                        </CardContent>
                    </Card>
                </div>

                <div className="text-xs text-muted-foreground mt-4 text-center">
                    {t('disk.note')}
                </div>
            </DialogContent>
        </Dialog>
    );
}
