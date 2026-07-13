import type {
    FileIntegrityActionErrorCode,
    FileIntegrityActionErrorEnvelope,
    FileIntegrityCoverageErrorCode,
    FileIntegrityDegradedReason,
    FileIntegrityErrorCount,
    FileIntegrityReenrollResult,
    FileIntegrityStatus,
    FileIntegrityStatusValue,
    FileIntegrityTrustResult,
} from "@/types";

type JsonRecord = Record<string, unknown>;

const MAX_SAFE_REVISION = Number.MAX_SAFE_INTEGER;
const MAX_TIMESTAMP = 253_402_300_799;
const MAX_TRACKED_FILES = 256;
const MAX_ERROR_CODES = 24;
const MAX_RESOLVED_EVENTS = 257;
const MAX_RESPONSE_BYTES = 4 * 1024;

const STATUS_VALUES = new Set<FileIntegrityStatusValue>([
    "disabled",
    "initializing",
    "healthy",
    "drift",
    "degraded",
]);
const COVERAGE_STATUSES = new Set(["disabled", "initializing", "full", "degraded"]);
const DEGRADED_REASONS = new Set<FileIntegrityDegradedReason>([
    "coverage_unavailable",
    "limit_exceeded",
    "deadline_exceeded",
    "baseline_corrupt",
    "unsupported_algorithm",
    "database_restore_required",
    "internal_error",
]);
const COVERAGE_ERROR_CODES = new Set<FileIntegrityCoverageErrorCode>([
    "permission_denied",
    "symlink",
    "not_regular",
    "file_too_large",
    "changed_during_read",
    "vanished_during_scan",
    "io_error",
    "tracked_file_limit",
    "scan_byte_limit",
    "deadline_exceeded",
    "directory_unreadable",
    "path_not_utf8",
    "path_too_long",
    "network_filesystem",
    "filesystem_unclassified",
    "untrusted_new_coverage",
    "no_observable_targets",
]);
const ACTION_ERROR_CODES = new Set<FileIntegrityActionErrorCode>([
    "invalid_request",
    "stale_generation",
    "not_initialized",
    "no_drift",
    "observation_not_trustable",
    "feature_disabled",
    "recovery_not_required",
    "unsupported_algorithm",
    "internal_error",
]);

function isRecord(value: unknown): value is JsonRecord {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expected: readonly string[]): boolean {
    const actual = Object.keys(value);
    return actual.length === expected.length
        && expected.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function isSafeInteger(value: unknown, min: number, max: number): value is number {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function readNullableSafeInteger(value: unknown, min: number, max: number): number | null | undefined {
    if (value === null) return null;
    return isSafeInteger(value, min, max) ? value : undefined;
}

function readErrorCounts(value: unknown): FileIntegrityErrorCount[] | null {
    if (!Array.isArray(value) || value.length > MAX_ERROR_CODES) return null;

    const result: FileIntegrityErrorCount[] = [];
    let previousCode: string | null = null;
    let total = 0;
    for (const item of value) {
        if (!isRecord(item) || !hasExactKeys(item, ["code", "count"])) return null;
        if (
            typeof item.code !== "string"
            || !COVERAGE_ERROR_CODES.has(item.code as FileIntegrityCoverageErrorCode)
            || !isSafeInteger(item.count, 1, MAX_TRACKED_FILES)
            || (previousCode !== null && previousCode >= item.code)
        ) return null;

        total += item.count;
        if (total > MAX_TRACKED_FILES) return null;
        previousCode = item.code;
        result.push({ code: item.code as FileIntegrityCoverageErrorCode, count: item.count });
    }
    return result;
}

function coverageIsEmpty(status: FileIntegrityStatus): boolean {
    return status.coverage.unavailable_target_count === 0 && status.coverage.error_counts.length === 0;
}

function isSoleUntrustedCoverage(status: FileIntegrityStatus): boolean {
    return status.coverage.unavailable_target_count === 0
        && status.coverage.error_counts.length === 1
        && status.coverage.error_counts[0].code === "untrusted_new_coverage";
}

export function decodeFileIntegrityStatus(value: unknown): FileIntegrityStatus | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "baseline_generation",
        "coverage",
        "degraded_reason",
        "drift_file_count",
        "last_scan_at",
        "observation_complete",
        "observed_generation",
        "re_enroll_available",
        "schema_version",
        "state_revision",
        "status",
        "tracked_file_count",
        "trust_available",
    ])) return null;
    if (!isRecord(value.coverage) || !hasExactKeys(value.coverage, [
        "error_counts",
        "status",
        "unavailable_target_count",
    ])) return null;

    const stateRevision = readNullableSafeInteger(value.state_revision, 0, MAX_SAFE_REVISION);
    const baselineGeneration = readNullableSafeInteger(value.baseline_generation, 0, MAX_SAFE_REVISION);
    const observedGeneration = readNullableSafeInteger(value.observed_generation, 0, MAX_SAFE_REVISION);
    const lastScanAt = readNullableSafeInteger(value.last_scan_at, 0, MAX_TIMESTAMP);
    const errorCounts = readErrorCounts(value.coverage.error_counts);
    if (
        value.schema_version !== 1
        || typeof value.status !== "string"
        || !STATUS_VALUES.has(value.status as FileIntegrityStatusValue)
        || stateRevision === undefined
        || baselineGeneration === undefined
        || observedGeneration === undefined
        || typeof value.observation_complete !== "boolean"
        || typeof value.trust_available !== "boolean"
        || typeof value.re_enroll_available !== "boolean"
        || !(value.degraded_reason === null
            || (typeof value.degraded_reason === "string"
                && DEGRADED_REASONS.has(value.degraded_reason as FileIntegrityDegradedReason)))
        || lastScanAt === undefined
        || !isSafeInteger(value.tracked_file_count, 0, MAX_TRACKED_FILES)
        || !isSafeInteger(value.drift_file_count, 0, MAX_TRACKED_FILES)
        || value.drift_file_count > value.tracked_file_count
        || typeof value.coverage.status !== "string"
        || !COVERAGE_STATUSES.has(value.coverage.status)
        || !isSafeInteger(value.coverage.unavailable_target_count, 0, MAX_TRACKED_FILES)
        || errorCounts === null
    ) return null;

    const decoded: FileIntegrityStatus = {
        schema_version: 1,
        status: value.status as FileIntegrityStatusValue,
        state_revision: stateRevision,
        baseline_generation: baselineGeneration,
        observed_generation: observedGeneration,
        observation_complete: value.observation_complete,
        trust_available: value.trust_available,
        re_enroll_available: value.re_enroll_available,
        degraded_reason: value.degraded_reason as FileIntegrityDegradedReason | null,
        last_scan_at: lastScanAt,
        tracked_file_count: value.tracked_file_count,
        drift_file_count: value.drift_file_count,
        coverage: {
            status: value.coverage.status as FileIntegrityStatus["coverage"]["status"],
            unavailable_target_count: value.coverage.unavailable_target_count,
            error_counts: errorCounts,
        },
    };

    if (decoded.status === "disabled") {
        return decoded.state_revision === null
            && decoded.baseline_generation === null
            && decoded.observed_generation === null
            && !decoded.observation_complete
            && !decoded.trust_available
            && !decoded.re_enroll_available
            && decoded.degraded_reason === null
            && decoded.last_scan_at === null
            && decoded.tracked_file_count === 0
            && decoded.drift_file_count === 0
            && decoded.coverage.status === "disabled"
            && coverageIsEmpty(decoded)
            ? decoded
            : null;
    }

    if (
        decoded.state_revision === null
        || decoded.baseline_generation === null
        || decoded.observed_generation === null
        || decoded.coverage.status === "disabled"
    ) return null;

    if (decoded.status === "initializing") {
        return decoded.baseline_generation === 0
            && decoded.observed_generation === 0
            && !decoded.observation_complete
            && !decoded.trust_available
            && !decoded.re_enroll_available
            && decoded.degraded_reason === null
            && decoded.last_scan_at === null
            && decoded.tracked_file_count === 0
            && decoded.drift_file_count === 0
            && decoded.coverage.status === "initializing"
            && coverageIsEmpty(decoded)
            ? decoded
            : null;
    }

    if (decoded.coverage.status === "initializing") return null;
    if (decoded.coverage.status === "full" && !coverageIsEmpty(decoded)) return null;

    if (decoded.status === "healthy") {
        return decoded.baseline_generation >= 1
            && decoded.observed_generation >= 1
            && decoded.observation_complete
            && !decoded.trust_available
            && !decoded.re_enroll_available
            && decoded.degraded_reason === null
            && decoded.last_scan_at !== null
            && decoded.drift_file_count === 0
            && decoded.coverage.status === "full"
            ? decoded
            : null;
    }

    if (decoded.status === "drift") {
        return decoded.baseline_generation >= 1
            && decoded.observed_generation >= 1
            && decoded.observation_complete
            && decoded.trust_available
            && !decoded.re_enroll_available
            && decoded.degraded_reason === null
            && decoded.last_scan_at !== null
            && decoded.drift_file_count >= 1
            && decoded.coverage.status === "full"
            ? decoded
            : null;
    }

    if (
        decoded.degraded_reason === null
        || decoded.last_scan_at === null
        || decoded.trust_available && decoded.re_enroll_available
    ) return null;
    if (decoded.trust_available && !(
        decoded.baseline_generation >= 1
        && decoded.observed_generation >= 1
        && decoded.observation_complete
        && decoded.degraded_reason === "coverage_unavailable"
        && decoded.coverage.status === "degraded"
        && isSoleUntrustedCoverage(decoded)
    )) return null;
    if (decoded.re_enroll_available && !(
        decoded.degraded_reason === "baseline_corrupt"
        && decoded.baseline_generation >= 1
        && decoded.observed_generation >= 1
        && decoded.observation_complete
        && decoded.coverage.status === "full"
        && coverageIsEmpty(decoded)
    )) return null;
    return decoded;
}

export function decodeFileIntegrityTrustResult(value: unknown): FileIntegrityTrustResult | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "baseline_generation",
        "observed_generation",
        "resolved_event_count",
        "result",
        "state_revision",
        "status",
        "trusted_at",
    ])) return null;
    if (
        value.result !== "trusted"
        || value.status !== "healthy"
        || !isSafeInteger(value.state_revision, 0, MAX_SAFE_REVISION)
        || !isSafeInteger(value.baseline_generation, 1, MAX_SAFE_REVISION)
        || !isSafeInteger(value.observed_generation, 1, MAX_SAFE_REVISION)
        || !isSafeInteger(value.trusted_at, 0, MAX_TIMESTAMP)
        || !isSafeInteger(value.resolved_event_count, 0, MAX_RESOLVED_EVENTS)
    ) return null;
    return value as unknown as FileIntegrityTrustResult;
}

export function decodeFileIntegrityReenrollResult(value: unknown): FileIntegrityReenrollResult | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "baseline_generation",
        "observed_generation",
        "reenrolled_at",
        "resolved_event_count",
        "result",
        "state_revision",
        "status",
    ])) return null;
    if (
        value.result !== "reenrolled"
        || value.status !== "healthy"
        || !isSafeInteger(value.state_revision, 0, MAX_SAFE_REVISION)
        || !isSafeInteger(value.baseline_generation, 1, MAX_SAFE_REVISION)
        || !isSafeInteger(value.observed_generation, 1, MAX_SAFE_REVISION)
        || !isSafeInteger(value.reenrolled_at, 0, MAX_TIMESTAMP)
        || !isSafeInteger(value.resolved_event_count, 0, MAX_RESOLVED_EVENTS)
    ) return null;
    return value as unknown as FileIntegrityReenrollResult;
}

export function decodeFileIntegrityActionError(value: unknown): FileIntegrityActionErrorEnvelope | null {
    if (!isRecord(value) || !hasExactKeys(value, ["error"]) || !isRecord(value.error)) return null;
    if (!hasExactKeys(value.error, [
        "baseline_generation",
        "code",
        "observed_generation",
        "state_revision",
        "status",
    ])) return null;

    const stateRevision = readNullableSafeInteger(value.error.state_revision, 0, MAX_SAFE_REVISION);
    const baselineGeneration = readNullableSafeInteger(value.error.baseline_generation, 0, MAX_SAFE_REVISION);
    const observedGeneration = readNullableSafeInteger(value.error.observed_generation, 0, MAX_SAFE_REVISION);
    if (
        typeof value.error.code !== "string"
        || !ACTION_ERROR_CODES.has(value.error.code as FileIntegrityActionErrorCode)
        || !(value.error.status === null
            || (typeof value.error.status === "string"
                && STATUS_VALUES.has(value.error.status as FileIntegrityStatusValue)))
        || stateRevision === undefined
        || baselineGeneration === undefined
        || observedGeneration === undefined
    ) return null;

    return {
        error: {
            code: value.error.code as FileIntegrityActionErrorCode,
            status: value.error.status as FileIntegrityStatusValue | null,
            state_revision: stateRevision,
            baseline_generation: baselineGeneration,
            observed_generation: observedGeneration,
        },
    };
}

export async function readBoundedFileIntegrityJson(response: Response): Promise<unknown> {
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && /^\d+$/.test(contentLength)
        && Number(contentLength) > MAX_RESPONSE_BYTES) {
        await response.body?.cancel().catch(() => undefined);
        throw new Error("file_integrity_response_too_large");
    }

    const reader = response.body?.getReader();
    if (reader === undefined) throw new Error("file_integrity_invalid_json");
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            totalBytes += value.byteLength;
            if (totalBytes > MAX_RESPONSE_BYTES) {
                await reader.cancel().catch(() => undefined);
                throw new Error("file_integrity_response_too_large");
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
        throw new Error("file_integrity_invalid_json");
    }
    try {
        return JSON.parse(raw) as unknown;
    } catch {
        throw new Error("file_integrity_invalid_json");
    }
}
