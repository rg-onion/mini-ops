import type {
    MetricsHistoryAggregate,
    MetricsHistoryPoint,
    MetricsHistoryResolution,
    MetricsHistoryResponse,
    MetricsHistoryWindow,
} from "@/types";

type JsonRecord = Record<string, unknown>;

const MAX_POINTS = 1_500;
const MAX_SAMPLE_COUNT = 12_000;
const MAX_TOTAL_SAMPLE_COUNT = 12_000;
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_TIMESTAMP = 253_402_300_799;
const MAX_FUTURE_SKEW_SECONDS = 24 * 60 * 60;
const MAX_BUCKET_START_TOLERANCE_SECONDS = 60 * 60;

const WINDOWS = new Set<MetricsHistoryWindow>(["1h", "6h", "24h", "7d"]);
const RESOLUTIONS = new Set<MetricsHistoryResolution>(["raw", "5m", "1h"]);

function isRecord(value: unknown): value is JsonRecord {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expected: readonly string[]): boolean {
    const actual = Object.keys(value);
    return actual.length === expected.length
        && expected.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function isSafeIntegerBetween(value: unknown, min: number, max: number): value is number {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function isPercent(value: unknown): value is number {
    return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
}

function decodeAggregate(value: unknown): MetricsHistoryAggregate | null {
    if (!isRecord(value) || !hasExactKeys(value, ["avg", "max"])) return null;
    if (!isPercent(value.avg) || !isPercent(value.max) || value.max < value.avg) return null;
    return { avg: value.avg, max: value.max };
}

function decodePoint(value: unknown): MetricsHistoryPoint | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "timestamp",
        "sample_count",
        "cpu_percent",
        "memory_percent",
        "disk_percent",
    ])) return null;
    if (
        !isSafeIntegerBetween(value.timestamp, 0, MAX_TIMESTAMP)
        || !isSafeIntegerBetween(value.sample_count, 1, MAX_SAMPLE_COUNT)
    ) return null;

    const cpuPercent = decodeAggregate(value.cpu_percent);
    const memoryPercent = value.memory_percent === null ? null : decodeAggregate(value.memory_percent);
    const diskPercent = value.disk_percent === null ? null : decodeAggregate(value.disk_percent);
    if (
        cpuPercent === null
        || (value.memory_percent !== null && memoryPercent === null)
        || (value.disk_percent !== null && diskPercent === null)
    ) return null;

    return {
        timestamp: value.timestamp,
        sample_count: value.sample_count,
        cpu_percent: cpuPercent,
        memory_percent: memoryPercent,
        disk_percent: diskPercent,
    };
}

export function decodeMetricsHistoryResponse(
    value: unknown,
    expectedWindow: MetricsHistoryWindow,
): MetricsHistoryResponse | null {
    const nowish = Math.floor(Date.now() / 1000) + MAX_FUTURE_SKEW_SECONDS;
    if (!isRecord(value) || !hasExactKeys(value, [
        "schema_version",
        "window",
        "resolution",
        "requested_start",
        "oldest_timestamp",
        "newest_timestamp",
        "partial",
        "points",
    ])) return null;
    if (
        value.schema_version !== 1
        || typeof value.window !== "string"
        || !WINDOWS.has(value.window as MetricsHistoryWindow)
        || value.window !== expectedWindow
        || typeof value.resolution !== "string"
        || !RESOLUTIONS.has(value.resolution as MetricsHistoryResolution)
        || !isSafeIntegerBetween(value.requested_start, 0, MAX_TIMESTAMP)
        || value.requested_start > nowish
        || typeof value.partial !== "boolean"
        || !Array.isArray(value.points)
        || value.points.length > MAX_POINTS
    ) return null;

    const oldestTimestamp = value.oldest_timestamp === null
        ? null
        : isSafeIntegerBetween(value.oldest_timestamp, 0, MAX_TIMESTAMP)
            ? value.oldest_timestamp
            : undefined;
    const newestTimestamp = value.newest_timestamp === null
        ? null
        : isSafeIntegerBetween(value.newest_timestamp, 0, MAX_TIMESTAMP)
            ? value.newest_timestamp
            : undefined;
    if (oldestTimestamp === undefined || newestTimestamp === undefined) return null;

    const decodedPoints: MetricsHistoryPoint[] = [];
    let previousTimestamp: number | null = null;
    let totalSampleCount = 0;
    for (const rawPoint of value.points) {
        const point = decodePoint(rawPoint);
        if (
            point === null
            || point.timestamp < value.requested_start - MAX_BUCKET_START_TOLERANCE_SECONDS
            || point.timestamp > nowish
            || (previousTimestamp !== null && point.timestamp < previousTimestamp)
        ) return null;

        totalSampleCount += point.sample_count;
        if (totalSampleCount > MAX_TOTAL_SAMPLE_COUNT) return null;
        previousTimestamp = point.timestamp;
        decodedPoints.push(point);
    }

    if (decodedPoints.length === 0) {
        if (oldestTimestamp !== null || newestTimestamp !== null || value.partial) return null;
    } else if (
        oldestTimestamp === null
        || newestTimestamp === null
        || oldestTimestamp < value.requested_start
        || newestTimestamp < oldestTimestamp
        || newestTimestamp > nowish
        || decodedPoints.some(point => point.timestamp > newestTimestamp)
    ) return null;

    return {
        schema_version: 1,
        window: value.window as MetricsHistoryWindow,
        resolution: value.resolution as MetricsHistoryResolution,
        requested_start: value.requested_start,
        oldest_timestamp: oldestTimestamp,
        newest_timestamp: newestTimestamp,
        partial: value.partial,
        points: decodedPoints,
    };
}

export async function readBoundedMetricsHistoryJson(response: Response): Promise<unknown> {
    const contentLength = response.headers.get("content-length");
    if (
        contentLength !== null
        && /^\d+$/.test(contentLength)
        && Number(contentLength) > MAX_RESPONSE_BYTES
    ) {
        await response.body?.cancel().catch(() => undefined);
        throw new Error("metrics_history_response_too_large");
    }

    const reader = response.body?.getReader();
    if (reader === undefined) throw new Error("metrics_history_invalid_json");
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            totalBytes += value.byteLength;
            if (totalBytes > MAX_RESPONSE_BYTES) {
                await reader.cancel().catch(() => undefined);
                throw new Error("metrics_history_response_too_large");
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }

    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }

    let raw: string;
    try {
        raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
        throw new Error("metrics_history_invalid_json");
    }
    try {
        return JSON.parse(raw) as unknown;
    } catch {
        throw new Error("metrics_history_invalid_json");
    }
}
