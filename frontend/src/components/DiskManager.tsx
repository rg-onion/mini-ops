import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "./ui/dialog";
import { HardDrive, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { useTranslation } from "react-i18next";
import { apiFetch } from "@/api";

interface DiskUsage {
    target_size: string;
    node_modules_size: string;
    docker_size: string;
    logs_size: string;
}

export function DiskManager() {
    const { t } = useTranslation();
    const [usage, setUsage] = useState<DiskUsage | null>(null);

    const fetchUsage = async () => {
        const res = await apiFetch("/disk/usage");
        if (res.ok) setUsage(await res.json());
    };

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

                <div className="mt-4 flex gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-200">
                    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{t('disk.cleanup_unavailable')}</span>
                </div>

                <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                    {/* Rust Artifacts */}
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">{t('disk.rust_build')}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{usage?.target_size || "..."}</div>
                            <p className="mt-4 text-xs text-muted-foreground">{t('disk.analysis_only')}</p>
                        </CardContent>
                    </Card>

                    {/* Node Modules */}
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">{t('disk.frontend_cache')}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{usage?.node_modules_size || "..."}</div>
                            <p className="mt-4 text-xs text-muted-foreground">{t('disk.analysis_only')}</p>
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
                            <p className="text-xs font-medium text-amber-700 dark:text-amber-300">
                                {t('disk.docker_unavailable')}
                            </p>
                        </CardContent>
                    </Card>

                    {/* Logs */}
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">{t('disk.system_logs')}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{usage?.logs_size || "..."}</div>
                            <p className="mt-4 text-xs text-muted-foreground">{t('disk.analysis_only')}</p>
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
