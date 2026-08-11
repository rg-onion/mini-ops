import { useId, useMemo } from "react";
import { useTranslation } from "react-i18next";
import {
    Area,
    AreaChart,
    CartesianGrid,
    Legend,
    Line,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { MetricsHistoryWindow } from "@/types";

export interface StatsChartDatum {
    timestamp: number;
    average: number | null;
    peak: number | null;
}

interface StatsChartProps {
    data: StatsChartDatum[];
    title: string;
    color: string;
    window: MetricsHistoryWindow;
}

function latestAvailablePoint(data: StatsChartDatum[]): StatsChartDatum | null {
    for (let index = data.length - 1; index >= 0; index -= 1) {
        if (data[index].average !== null && data[index].peak !== null) return data[index];
    }
    return null;
}

export function StatsChart({ data, title, color, window }: StatsChartProps) {
    const { t, i18n } = useTranslation();
    const gradientId = `metrics-${useId().replaceAll(":", "")}`;
    const locale = i18n.resolvedLanguage ?? i18n.language;
    const hasData = data.some(point => point.average !== null && point.peak !== null);
    const availablePointCount = data.filter(point => point.average !== null && point.peak !== null).length;
    const latest = latestAvailablePoint(data);
    const axisFormatter = useMemo(() => new Intl.DateTimeFormat(locale, window === "1h" || window === "6h"
        ? { hour: "2-digit", minute: "2-digit" }
        : { day: "2-digit", month: "short", hour: "2-digit" }), [locale, window]);
    const tooltipFormatter = useMemo(() => new Intl.DateTimeFormat(locale, {
        dateStyle: "medium",
        timeStyle: "short",
    }), [locale]);
    const summary = latest === null
        ? t("dashboard.history_metric_empty")
        : t("dashboard.history_chart_summary", {
            title,
            count: availablePointCount,
            average: latest.average?.toFixed(1),
            peak: latest.peak?.toFixed(1),
        });

    return (
        <Card className="min-w-0">
            <CardHeader className="px-4 pb-2 pt-5 sm:px-6">
                <CardTitle className="text-base sm:text-lg">{title}</CardTitle>
            </CardHeader>
            <CardContent className="px-2 pb-4 sm:px-4">
                {!hasData ? (
                    <div className="flex h-[240px] items-center justify-center px-4 text-center text-sm text-muted-foreground sm:h-[270px]">
                        {t("dashboard.history_metric_empty")}
                    </div>
                ) : (
                    <div className="h-[240px] min-w-0 w-full sm:h-[270px]" role="img" aria-label={summary}>
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={data} margin={{ top: 8, right: 22, left: 4, bottom: 0 }}>
                                <defs>
                                    <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                                        <stop offset="95%" stopColor={color} stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid
                                    strokeDasharray="3 3"
                                    vertical={false}
                                    stroke="hsl(var(--border))"
                                    opacity={0.5}
                                />
                                <XAxis
                                    dataKey="timestamp"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    interval="preserveStartEnd"
                                    minTickGap={24}
                                    tick={{ fill: "hsl(var(--muted-foreground))" }}
                                    tickFormatter={value => axisFormatter.format(Number(value) * 1000)}
                                />
                                <YAxis
                                    width={40}
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    tickFormatter={value => `${value}%`}
                                    domain={[0, 100]}
                                    tick={{ fill: "hsl(var(--muted-foreground))" }}
                                />
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: "hsl(var(--popover))",
                                        borderRadius: "var(--radius)",
                                        border: "1px solid hsl(var(--border))",
                                        color: "hsl(var(--popover-foreground))",
                                        boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
                                    }}
                                    itemStyle={{ color: "hsl(var(--foreground))" }}
                                    labelStyle={{
                                        color: "hsl(var(--muted-foreground))",
                                        marginBottom: "0.25rem",
                                    }}
                                    formatter={value => `${Number(value).toFixed(1)}%`}
                                    labelFormatter={value => tooltipFormatter.format(Number(value) * 1000)}
                                />
                                <Legend verticalAlign="top" height={32} iconType="plainline" />
                                <Area
                                    type="monotone"
                                    dataKey="average"
                                    name={t("dashboard.history_average")}
                                    stroke={color}
                                    fill={`url(#${gradientId})`}
                                    fillOpacity={1}
                                    strokeWidth={2}
                                    dot={false}
                                    connectNulls={false}
                                    isAnimationActive={false}
                                />
                                <Line
                                    type="monotone"
                                    dataKey="peak"
                                    name={t("dashboard.history_peak")}
                                    stroke="#f97316"
                                    strokeWidth={1.75}
                                    strokeDasharray="5 4"
                                    dot={false}
                                    connectNulls={false}
                                    isAnimationActive={false}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
