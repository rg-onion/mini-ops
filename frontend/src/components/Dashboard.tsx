import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
    Activity,
    AlertTriangle,
    Cpu,
    HardDrive,
    LayoutDashboard,
    LoaderCircle,
    RefreshCcw,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { apiFetch } from "@/api";
import { Button } from "@/components/ui/button";
import { decodeMetricsHistoryResponse, readBoundedMetricsHistoryJson } from "@/lib/metricsHistory";
import type {
    MetricsHistoryAggregate,
    MetricsHistoryPoint,
    MetricsHistoryResponse,
    MetricsHistoryWindow,
    SystemStats,
} from "@/types";
import { StatsCard } from "./StatsCard";
import { StatsChart, type StatsChartDatum } from "./StatsChart";

const HISTORY_WINDOWS: MetricsHistoryWindow[] = ["1h", "6h", "24h", "7d"];

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

async function fetchHistory(window: MetricsHistoryWindow): Promise<MetricsHistoryResponse> {
    const response = await apiFetch(`/stats/history?window=${window}&resolution=auto`);
    if (!response.ok) throw new Error("metrics_history_request_failed");
    const payload = await readBoundedMetricsHistoryJson(response);
    const history = decodeMetricsHistoryResponse(payload, window);
    if (history === null) throw new Error("metrics_history_invalid_response");
    return history;
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

function formatTimestamp(timestamp: number, locale: string) {
    return new Intl.DateTimeFormat(locale, {
        dateStyle: "medium",
        timeStyle: "short",
    }).format(timestamp * 1000);
}

function chartData(
    points: MetricsHistoryPoint[],
    selectAggregate: (point: MetricsHistoryPoint) => MetricsHistoryAggregate | null,
): StatsChartDatum[] {
    return points.map(point => {
        const aggregate = selectAggregate(point);
        return {
            timestamp: point.timestamp,
            average: aggregate?.avg ?? null,
            peak: aggregate?.max ?? null,
        };
    });
}

export default function Dashboard() {
    const { t, i18n } = useTranslation();
    const [historyWindow, setHistoryWindow] = useState<MetricsHistoryWindow>("1h");
    const statsQuery = useQuery({
        queryKey: ["metrics-current"],
        queryFn: fetchStats,
        refetchInterval: 5000,
    });
    const historyQuery = useQuery({
        queryKey: ["metrics-history", historyWindow],
        queryFn: () => fetchHistory(historyWindow),
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
    const diskFree = displayStats === undefined
        ? undefined
        : displayStats.disk_total - displayStats.disk_used;
    const history = historyQuery.data;
    const historyPoints = history?.points ?? [];
    const cpuHistory = chartData(historyPoints, point => point.cpu_percent);
    const memoryHistory = chartData(historyPoints, point => point.memory_percent);
    const diskHistory = chartData(historyPoints, point => point.disk_percent);
    const locale = i18n.resolvedLanguage ?? i18n.language;

    return (
        <div className="flex-1 space-y-6">
            <div className="flex items-center justify-between gap-4">
                <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">{t("common.dashboard")}</h2>
                <LayoutDashboard className="h-6 w-6 shrink-0 text-muted-foreground" aria-hidden="true" />
            </div>

            {statsUnavailable && (
                <div
                    role="alert"
                    className="flex flex-col items-start justify-between gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-700 sm:flex-row sm:items-center dark:text-red-300"
                >
                    <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
                        <span>{t("dashboard.current_error")}</span>
                    </div>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => statsQuery.refetch()}
                        disabled={statsQuery.isFetching}
                    >
                        <RefreshCcw className="h-3.5 w-3.5" aria-hidden="true" />
                        {t("common.retry")}
                    </Button>
                </div>
            )}

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3" aria-busy={statsQuery.isLoading}>
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
                    description={currentDescription ?? t("dashboard.disk_usage", {
                        used: formatBytes(displayStats?.disk_used),
                        total: formatBytes(displayStats?.disk_total),
                        free: formatBytes(diskFree),
                    })}
                />
            </div>

            <section className="space-y-4" aria-labelledby="metrics-history-title">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                    <div className="min-w-0">
                        <h3 id="metrics-history-title" className="text-xl font-semibold tracking-tight">
                            {t("dashboard.history_title")}
                        </h3>
                        {history !== undefined && history.points.length > 0 && (
                            <p className="mt-1 text-xs text-muted-foreground">
                                {t("dashboard.history_meta", {
                                    count: history.points.length,
                                    resolution: t(`dashboard.history_resolutions.${history.resolution}`),
                                })}
                            </p>
                        )}
                    </div>
                    <div className="flex flex-col items-start gap-2 sm:items-end">
                        {historyQuery.isFetching && !historyQuery.isLoading && (
                            <span role="status" className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                                {t("dashboard.history_refreshing")}
                            </span>
                        )}
                        <div
                            role="group"
                            aria-label={t("dashboard.history_range")}
                            className="grid w-full grid-cols-4 gap-1 rounded-lg border bg-muted/40 p-1 sm:w-auto"
                        >
                            {HISTORY_WINDOWS.map(window => (
                                <Button
                                    key={window}
                                    type="button"
                                    size="sm"
                                    variant={historyWindow === window ? "default" : "ghost"}
                                    aria-pressed={historyWindow === window}
                                    onClick={() => setHistoryWindow(window)}
                                    className="min-w-14 px-2"
                                >
                                    {t(`dashboard.history_windows.${window}`)}
                                </Button>
                            ))}
                        </div>
                    </div>
                </div>

                {historyQuery.isLoading ? (
                    <div
                        aria-busy="true"
                        className="flex items-center justify-center gap-2 rounded-md border px-4 py-10 text-sm text-muted-foreground"
                    >
                        <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />
                        <span>{t("dashboard.history_loading")}</span>
                    </div>
                ) : historyQuery.isError || history === undefined ? (
                    <div
                        role="alert"
                        className="flex flex-col items-center justify-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-4 py-8 text-center text-sm text-red-700 dark:text-red-300"
                    >
                        <div className="flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
                            <span>{t("dashboard.history_error")}</span>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => historyQuery.refetch()}
                            disabled={historyQuery.isFetching}
                        >
                            <RefreshCcw className="h-3.5 w-3.5" aria-hidden="true" />
                            {t("common.retry")}
                        </Button>
                    </div>
                ) : history.points.length === 0 ? (
                    <div className="rounded-md border px-4 py-10 text-center text-sm text-muted-foreground">
                        {t("dashboard.history_empty")}
                    </div>
                ) : (
                    <div className="space-y-4">
                        {history.partial && history.oldest_timestamp !== null && (
                            <div
                                role="status"
                                className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-200"
                            >
                                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                                <span>
                                    {t("dashboard.history_partial", {
                                        time: formatTimestamp(history.oldest_timestamp, locale),
                                    })}
                                </span>
                            </div>
                        )}
                        <div className="grid min-w-0 gap-4 xl:grid-cols-3">
                            <StatsChart
                                title={t("dashboard.cpu_history")}
                                data={cpuHistory}
                                color="#2563eb"
                                window={historyWindow}
                            />
                            <StatsChart
                                title={t("dashboard.ram_history")}
                                data={memoryHistory}
                                color="#7c3aed"
                                window={historyWindow}
                            />
                            <StatsChart
                                title={t("dashboard.disk_history")}
                                data={diskHistory}
                                color="#059669"
                                window={historyWindow}
                            />
                        </div>
                    </div>
                )}
            </section>
        </div>
    );
}
