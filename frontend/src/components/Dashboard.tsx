import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Cpu, HardDrive, LayoutDashboard, LoaderCircle, RefreshCcw } from "lucide-react";
import { useTranslation } from "react-i18next";

import { apiFetch } from "@/api";
import { Button } from "@/components/ui/button";
import type { SystemStats } from "@/types";
import { StatsCard } from "./StatsCard";
import { StatsChart } from "./StatsChart";

function isSystemStats(value: unknown): value is SystemStats {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const stats = value as Record<string, unknown>;
    return typeof stats.cpu_usage === "number"
        && Number.isFinite(stats.cpu_usage)
        && stats.cpu_usage >= 0
        && typeof stats.memory_used === "number"
        && Number.isFinite(stats.memory_used)
        && stats.memory_used >= 0
        && typeof stats.memory_total === "number"
        && Number.isFinite(stats.memory_total)
        && stats.memory_total > 0
        && stats.memory_used <= stats.memory_total
        && typeof stats.disk_used === "number"
        && Number.isFinite(stats.disk_used)
        && stats.disk_used >= 0
        && typeof stats.disk_total === "number"
        && Number.isFinite(stats.disk_total)
        && stats.disk_total > 0
        && stats.disk_used <= stats.disk_total
        && typeof stats.timestamp === "number"
        && Number.isSafeInteger(stats.timestamp)
        && stats.timestamp >= 0;
}

async function fetchStats(): Promise<SystemStats> {
    const response = await apiFetch("/stats");
    if (!response.ok) throw new Error("stats_request_failed");
    const payload: unknown = await response.json();
    if (!isSystemStats(payload)) throw new Error("stats_invalid_response");
    return payload;
}

async function fetchHistory(): Promise<SystemStats[]> {
    const response = await apiFetch("/stats/history");
    if (!response.ok) throw new Error("metrics_history_request_failed");
    const payload: unknown = await response.json();
    if (!Array.isArray(payload) || !payload.every(isSystemStats)) {
        throw new Error("metrics_history_invalid_response");
    }
    return payload;
}

function formatBytes(bytes: number | undefined) {
    if (bytes === undefined || !Number.isFinite(bytes) || bytes < 0) return "—";
    if (bytes === 0) return "0 B";
    const unit = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(unit)), sizes.length - 1);
    return `${parseFloat((bytes / Math.pow(unit, index)).toFixed(2))} ${sizes[index]}`;
}

function formatPercent(value: number | undefined, total?: number) {
    if (value === undefined || !Number.isFinite(value)) return "—";
    if (total !== undefined) {
        if (!Number.isFinite(total) || total <= 0) return "—";
        return `${((value / total) * 100).toFixed(1)}%`;
    }
    return `${value.toFixed(1)}%`;
}

export default function Dashboard() {
    const { t } = useTranslation();
    const statsQuery = useQuery({
        queryKey: ["metrics-current"],
        queryFn: fetchStats,
        refetchInterval: 5000,
    });
    const historyQuery = useQuery({
        queryKey: ["metrics-history"],
        queryFn: fetchHistory,
        refetchInterval: 30000,
    });

    const stats = statsQuery.data;
    const statsUnavailable = statsQuery.isError || (!statsQuery.isLoading && !stats);
    const displayStats = statsUnavailable ? undefined : stats;
    const currentDescription = statsQuery.isLoading
        ? t("common.loading")
        : statsUnavailable
            ? t("dashboard.current_unavailable")
            : undefined;

    return (
        <div className="flex-1 space-y-4 p-8 pt-6">
            <div className="flex items-center justify-between space-y-2">
                <h2 className="text-3xl font-bold tracking-tight">{t("common.dashboard")}</h2>
                <div className="flex items-center space-x-2">
                    <LayoutDashboard className="h-6 w-6 text-muted-foreground" />
                </div>
            </div>

            {statsUnavailable && (
                <div
                    role="alert"
                    className="flex flex-col items-start justify-between gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-700 sm:flex-row sm:items-center dark:text-red-300"
                >
                    <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 shrink-0" />
                        <span>{t("dashboard.current_error")}</span>
                    </div>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => statsQuery.refetch()}
                        disabled={statsQuery.isFetching}
                    >
                        <RefreshCcw className="h-3.5 w-3.5" />
                        {t("common.retry")}
                    </Button>
                </div>
            )}

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3" aria-busy={statsQuery.isLoading}>
                <StatsCard
                    title={t("common.cpu")}
                    value={statsQuery.isLoading ? "—" : formatPercent(displayStats?.cpu_usage)}
                    icon={<Cpu className="h-4 w-4 text-muted-foreground" />}
                    description={currentDescription ?? t("common.real_time_load")}
                />
                <StatsCard
                    title={t("common.ram")}
                    value={statsQuery.isLoading ? "—" : formatPercent(displayStats?.memory_used, displayStats?.memory_total)}
                    icon={<Activity className="h-4 w-4 text-muted-foreground" />}
                    description={currentDescription ?? `${formatBytes(displayStats?.memory_used)} / ${formatBytes(displayStats?.memory_total)}`}
                />
                <StatsCard
                    title={t("common.disk")}
                    value={statsQuery.isLoading ? "—" : formatPercent(displayStats?.disk_used, displayStats?.disk_total)}
                    icon={<HardDrive className="h-4 w-4 text-muted-foreground" />}
                    description={currentDescription ?? `${formatBytes(displayStats?.disk_used)} / ${formatBytes(displayStats?.disk_total)}`}
                />
            </div>

            <div className="grid gap-4">
                <div className="col-span-full">
                    {historyQuery.isLoading ? (
                        <div
                            aria-busy="true"
                            className="flex items-center justify-center gap-2 rounded-md border px-4 py-10 text-sm text-muted-foreground"
                        >
                            <LoaderCircle className="h-4 w-4 animate-spin" />
                            <span>{t("dashboard.history_loading")}</span>
                        </div>
                    ) : historyQuery.isError || !historyQuery.data ? (
                        <div
                            role="alert"
                            className="flex flex-col items-center justify-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-4 py-8 text-center text-sm text-red-700 dark:text-red-300"
                        >
                            <div className="flex items-center gap-2">
                                <AlertTriangle className="h-4 w-4" />
                                <span>{t("dashboard.history_error")}</span>
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
                    ) : historyQuery.data.length === 0 ? (
                        <div className="rounded-md border px-4 py-10 text-center text-sm text-muted-foreground">
                            {t("dashboard.history_empty")}
                        </div>
                    ) : (
                        <div className="grid gap-4 md:grid-cols-2">
                            <StatsChart
                                title={t("common.cpu_history")}
                                data={historyQuery.data}
                                dataKey="cpu_usage"
                                color="#3b82f6"
                            />
                            <StatsChart
                                title={t("common.ram_history")}
                                data={historyQuery.data
                                    .filter(item => item.memory_total > 0)
                                    .map(item => ({
                                        ...item,
                                        ram_percent: (item.memory_used / item.memory_total) * 100,
                                    }))}
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
