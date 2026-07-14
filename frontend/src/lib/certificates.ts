import type {
    CertificateCurrentObservation,
    CertificateExpiry,
    CertificateHostname,
    CertificateMonitorState,
    CertificateMonitorStatus,
    CertificateProbeErrorCode,
    CertificateReachability,
    CertificateRefreshErrorCode,
    CertificateRefreshErrorEnvelope,
    CertificateRefreshResult,
    CertificateTargetStatus,
    CertificateTrust,
} from "@/types";

type JsonRecord = Record<string, unknown>;

const MAX_TIMESTAMP = 253_402_300_799;
const MAX_TARGETS = 32;
const MAX_RESPONSE_BYTES = 64 * 1024;
const TARGET_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,62}$/;

const MONITOR_STATES = new Set<CertificateMonitorState>(["disabled", "enabled"]);
const REACHABILITY_VALUES = new Set<CertificateReachability>(["reachable", "unknown"]);
const TRUST_VALUES = new Set<CertificateTrust>(["valid", "invalid", "unknown"]);
const HOSTNAME_VALUES = new Set<CertificateHostname>(["match", "mismatch", "unknown"]);
const EXPIRY_VALUES = new Set<CertificateExpiry>([
    "healthy",
    "warning",
    "critical",
    "expired",
    "not_yet_valid",
    "unknown",
]);
const PROBE_ERROR_CODES = new Set<CertificateProbeErrorCode>([
    "dns_timeout",
    "dns_failed",
    "connect_timeout",
    "connect_refused",
    "connect_failed",
    "tls_timeout",
    "tls_handshake_failed",
    "certificate_missing",
    "certificate_parse_failed",
    "unsupported_protocol",
    "cancelled",
    "internal_error",
]);
const REFRESH_ERROR_CODES = new Set<CertificateRefreshErrorCode>([
    "invalid_request",
    "certificate_monitor_disabled",
    "certificate_target_not_found",
    "certificate_refresh_busy",
    "certificate_refresh_cooldown",
    "certificate_monitor_unavailable",
]);

function isRecord(value: unknown): value is JsonRecord {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expected: readonly string[]) {
    const keys = Object.keys(value);
    return keys.length === expected.length && expected.every(key => Object.hasOwn(value, key));
}

function isIntegerBetween(value: unknown, min: number, max: number): value is number {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function isNullableTimestamp(value: unknown): value is number | null {
    return value === null || isIntegerBetween(value, 0, MAX_TIMESTAMP);
}

function isBoundedString(value: unknown, maxLength: number): value is string {
    return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function decodeObservation(value: unknown): CertificateCurrentObservation | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "schema_version",
        "checked_at",
        "duration_ms",
        "last_success_at",
        "reachability",
        "trust",
        "hostname",
        "expiry",
        "not_before",
        "not_after",
        "remaining_seconds",
        "error_code",
    ])) return null;
    if (
        value.schema_version !== 1
        || !isIntegerBetween(value.checked_at, 0, MAX_TIMESTAMP)
        || !isIntegerBetween(value.duration_ms, 0, 60_000)
        || !isNullableTimestamp(value.last_success_at)
        || typeof value.reachability !== "string"
        || !REACHABILITY_VALUES.has(value.reachability as CertificateReachability)
        || typeof value.trust !== "string"
        || !TRUST_VALUES.has(value.trust as CertificateTrust)
        || typeof value.hostname !== "string"
        || !HOSTNAME_VALUES.has(value.hostname as CertificateHostname)
        || typeof value.expiry !== "string"
        || !EXPIRY_VALUES.has(value.expiry as CertificateExpiry)
        || !isNullableTimestamp(value.not_before)
        || !isNullableTimestamp(value.not_after)
        || !(value.remaining_seconds === null
            || isIntegerBetween(value.remaining_seconds, -MAX_TIMESTAMP, MAX_TIMESTAMP))
        || !(value.error_code === null
            || (typeof value.error_code === "string"
                && PROBE_ERROR_CODES.has(value.error_code as CertificateProbeErrorCode)))
    ) return null;

    if (value.error_code === null) {
        if (
            value.reachability !== "reachable"
            || value.not_before === null
            || value.not_after === null
            || value.remaining_seconds === null
            || value.not_after <= value.not_before
            || value.remaining_seconds !== value.not_after - value.checked_at
        ) return null;
    } else if (
        value.not_before !== null
        || value.not_after !== null
        || value.remaining_seconds !== null
        || value.trust !== "unknown"
        || value.hostname !== "unknown"
        || value.expiry !== "unknown"
    ) return null;

    return value as unknown as CertificateCurrentObservation;
}

function decodeTarget(value: unknown): CertificateTargetStatus | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "target_id",
        "label",
        "connect_host",
        "port",
        "server_name",
        "observation",
    ])) return null;
    if (
        typeof value.target_id !== "string"
        || !TARGET_ID_PATTERN.test(value.target_id)
        || !isBoundedString(value.label, 128)
        || !isBoundedString(value.connect_host, 253)
        || !isIntegerBetween(value.port, 1, 65_535)
        || !isBoundedString(value.server_name, 253)
    ) return null;
    const observation = value.observation === null ? null : decodeObservation(value.observation);
    if (value.observation !== null && observation === null) return null;
    return {
        target_id: value.target_id,
        label: value.label,
        connect_host: value.connect_host,
        port: value.port,
        server_name: value.server_name,
        observation,
    };
}

export function decodeCertificateMonitorStatus(value: unknown): CertificateMonitorStatus | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "schema_version",
        "status",
        "interval_seconds",
        "refresh_cooldown_seconds",
        "earliest_expiry_at",
        "targets",
    ])) return null;
    if (
        value.schema_version !== 1
        || typeof value.status !== "string"
        || !MONITOR_STATES.has(value.status as CertificateMonitorState)
        || !isIntegerBetween(value.refresh_cooldown_seconds, 1, 3_600)
        || !isNullableTimestamp(value.earliest_expiry_at)
        || !Array.isArray(value.targets)
        || value.targets.length > MAX_TARGETS
    ) return null;

    if (value.status === "disabled") {
        if (value.interval_seconds !== null || value.earliest_expiry_at !== null || value.targets.length !== 0) {
            return null;
        }
    } else if (
        !isIntegerBetween(value.interval_seconds, 300, 86_400)
        || value.targets.length === 0
    ) return null;

    const targets = value.targets.map(decodeTarget);
    if (targets.some(target => target === null)) return null;
    const decodedTargets = targets as CertificateTargetStatus[];
    const ids = new Set(decodedTargets.map(target => target.target_id));
    if (ids.size !== decodedTargets.length) return null;
    const expirations = decodedTargets
        .map(target => target.observation?.not_after ?? null)
        .filter((expiration): expiration is number => expiration !== null);
    const earliest = expirations.length > 0 ? Math.min(...expirations) : null;
    if (value.earliest_expiry_at !== earliest) return null;

    return {
        schema_version: 1,
        status: value.status as CertificateMonitorState,
        interval_seconds: value.interval_seconds as number | null,
        refresh_cooldown_seconds: value.refresh_cooldown_seconds,
        earliest_expiry_at: value.earliest_expiry_at,
        targets: decodedTargets,
    };
}

export function decodeCertificateRefreshResult(value: unknown): CertificateRefreshResult | null {
    if (!isRecord(value) || !hasExactKeys(value, ["schema_version", "result", "target"])) return null;
    if (value.schema_version !== 1 || value.result !== "refreshed") return null;
    const target = decodeTarget(value.target);
    if (target === null || target.observation === null) return null;
    return {
        schema_version: 1,
        result: "refreshed",
        target: { ...target, observation: target.observation },
    };
}

export function decodeCertificateRefreshError(value: unknown): CertificateRefreshErrorEnvelope | null {
    if (!isRecord(value) || !hasExactKeys(value, ["error"]) || !isRecord(value.error)
        || !hasExactKeys(value.error, ["code"]) || typeof value.error.code !== "string"
        || !REFRESH_ERROR_CODES.has(value.error.code as CertificateRefreshErrorCode)) return null;
    return { error: { code: value.error.code as CertificateRefreshErrorCode } };
}

export async function readBoundedCertificateJson(response: Response): Promise<unknown> {
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && /^\d+$/.test(contentLength)
        && Number(contentLength) > MAX_RESPONSE_BYTES) {
        await response.body?.cancel().catch(() => undefined);
        throw new Error("certificate_response_too_large");
    }

    const reader = response.body?.getReader();
    if (reader === undefined) throw new Error("certificate_invalid_json");
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            totalBytes += value.byteLength;
            if (totalBytes > MAX_RESPONSE_BYTES) {
                await reader.cancel().catch(() => undefined);
                throw new Error("certificate_response_too_large");
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
        throw new Error("certificate_invalid_json");
    }
    try {
        return JSON.parse(raw) as unknown;
    } catch {
        throw new Error("certificate_invalid_json");
    }
}
