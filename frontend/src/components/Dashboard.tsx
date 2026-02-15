import { useQuery } from "@tanstack/react-query";
import { StatsCard } from "./StatsCard";
import { StatsChart } from "./StatsChart";
import { Activity, Cpu, HardDrive, LayoutDashboard } from "lucide-react";
import type { SystemStats } from "@/types";
import { apiFetch } from "@/api";
import { useTranslation } from "react-i18next";

async function fetchStats(): Promise<SystemStats> {
    const res = await apiFetch("/stats");
    return res.json();
}

async function fetchHistory(): Promise<SystemStats[]> {
    const res = await apiFetch("/stats/history");
    return res.json();
}

export default function Dashboard() {
    const { t } = useTranslation();
    const { data: stats } = useQuery({
        queryKey: ["stats"],
        queryFn: fetchStats,
        refetchInterval: 5000, // Poll every 5s
    });

    const { data: history } = useQuery({
        queryKey: ["history"],
        queryFn: fetchHistory,
        refetchInterval: 30000, // Poll every 30s
    });

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    };

    const cpuUsage = stats?.cpu_usage?.toFixed(1) || "0.0";
    const ramUsage = stats ? ((stats.memory_used / stats.memory_total) * 100).toFixed(1) : "0.0";
    const diskUsage = stats ? ((stats.disk_used / stats.disk_total) * 100).toFixed(1) : "0.0";

    return (
        <div className="flex-1 space-y-4 p-8 pt-6">
            <div className="flex items-center justify-between space-y-2">
                <h2 className="text-3xl font-bold tracking-tight">{t('common.dashboard')}</h2>
                <div className="flex items-center space-x-2">
                    <LayoutDashboard className="h-6 w-6 text-muted-foreground" />
                </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                <StatsCard
                    title={t('common.cpu')}
                    value={`${cpuUsage}%`}
                    icon={<Cpu className="h-4 w-4 text-muted-foreground" />}
                    description={t('common.real_time_load')}
                />
                <StatsCard
                    title={t('common.ram')}
                    value={`${ramUsage}%`}
                    icon={<Activity className="h-4 w-4 text-muted-foreground" />}
                    description={`${formatBytes(stats?.memory_used || 0)} / ${formatBytes(stats?.memory_total || 0)}`}
                />
                <StatsCard
                    title={t('common.disk')}
                    value={`${diskUsage}%`}
                    icon={<HardDrive className="h-4 w-4 text-muted-foreground" />}
                    description={`${formatBytes(stats?.disk_used || 0)} / ${formatBytes(stats?.disk_total || 0)}`}
                />
            </div>

            <div className="grid gap-4">
                <div className="col-span-full">
                    {history && (
                        <div className="grid gap-4 md:grid-cols-2">
                            <StatsChart
                                title={t('common.cpu_history')}
                                data={history}
                                dataKey="cpu_usage"
                                color="#3b82f6"
                            />
                            <StatsChart
                                title={t('common.ram_history')}
                                data={history.map(h => ({ ...h, ram_percent: (h.memory_used / h.memory_total) * 100 }))}
                                dataKey="ram_percent"
                                color="#8b5cf6"
                            />
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
