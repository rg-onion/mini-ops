import type {
    AuditSecurityEventEvidenceData,
    FileIntegrityBaselineReenrolledEvidenceData,
    FileIntegrityCoverageDegradedEvidenceData,
    FileIntegrityCoverageErrorCode,
    FileIntegrityDegradedReason,
    FileIntegrityErrorCount,
    NotificationDeliveryErrorCode,
    NotificationDeliveryStatus,
    NotificationSecurityEventEvidenceData,
    SecurityEvent,
    SecurityEventEvidence,
    SecurityAuditResultKind,
    SensitiveFileChangedEvidenceData,
    SensitiveFileChangeKind,
    SensitiveFileCompleteEvidenceMetadata,
    SensitiveFileObservationError,
    SensitiveFileObservedEvidenceMetadata,
    SshSecurityEventEvidenceData,
} from "@/types";
import { auditResultKindMatchesStatus } from "@/lib/securityAudit";

type JsonRecord = Record<string, unknown>;

const MAX_TIMESTAMP = 253_402_300_799;
const MAX_EVIDENCE_BYTES = 64 * 1024;
const UTF8 = new TextEncoder();
const MACHINE_IDENTIFIER = /^[a-z0-9._-]+$/u;
const PATH_ID = /^path-v1:[0-9a-f]{64}$/u;
const SECURITY_EVENT_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const SECURITY_EVENT_STATUSES = new Set(["open", "acknowledged", "resolved"]);
const EVIDENCE_ERROR_CODES = new Set(["unsupported_schema_version", "invalid_stored_payload"]);
const SSH_METHODS = new Set(["ssh", "password", "publickey", "keyboard-interactive", "unknown"]);
const NOTIFICATION_DELIVERY_STATUSES = new Set<NotificationDeliveryStatus>([
    "pending",
    "sending",
    "sent",
    "failed",
    "disabled",
    "suppressed",
]);
const NOTIFICATION_DELIVERY_ERROR_CODES = new Set<NotificationDeliveryErrorCode>([
    "dns",
    "connect_timeout",
    "request_timeout",
    "transport",
    "http_4xx",
    "http_5xx",
    "response_too_large",
    "invalid_response",
    "provider_rejected",
    "lease_expired",
    "retention_expired",
]);
const AUDIT_METADATA_KEYS = new Set([
    "result_kind",
    "coverage_status",
    "suspicious_ports",
    "unexpected_listeners",
    "open_ports",
    "listeners",
    "loopback_listeners",
    "non_loopback_listeners",
    "wildcard_listeners",
    "allowed_public_ports",
    "allowed_loopback_ports",
    "invalid_allowed_port_count",
    "public_listeners",
    "risk_count",
    "critical_risks",
    "high_risks",
    "medium_risks",
    "low_risks",
    "info_risks",
]);
const AUDIT_RESULT_KINDS = new Set<SecurityAuditResultKind>([
    "pass",
    "finding",
    "recommendation",
    "unverified",
    "coverage",
]);
const AUDIT_PORT_KEYS = new Set([
    "suspicious_ports",
    "open_ports",
    "allowed_public_ports",
    "allowed_loopback_ports",
]);
const AUDIT_COUNT_KEYS = new Set(["invalid_allowed_port_count", "risk_count"]);
const PRIVATE_MARKERS = [
    "command_output=",
    "raw_command=",
    "raw_error=",
    "sql_error=",
    "stdout=",
    "stderr=",
    "contents=",
    "content_digest=",
    "excerpt=",
    "symlink_target=",
];
const FILE_CHANGE_KINDS = new Set<SensitiveFileChangeKind>([
    "added",
    "content_changed",
    "owner_changed",
    "permissions_changed",
    "removed",
    "type_changed",
    "unreadable",
]);
const FILE_OBSERVATION_ERRORS = new Set<SensitiveFileObservationError>([
    "permission_denied",
    "symlink",
    "not_regular",
    "file_too_large",
    "changed_during_read",
    "vanished_during_scan",
    "io_error",
]);
const FILE_INTEGRITY_DEGRADED_REASONS = new Set<FileIntegrityDegradedReason>([
    "coverage_unavailable",
    "limit_exceeded",
    "deadline_exceeded",
    "baseline_corrupt",
    "unsupported_algorithm",
    "database_restore_required",
    "internal_error",
]);
const HIGH_INTEGRITY_DEGRADED_REASONS = new Set<FileIntegrityDegradedReason>([
    "baseline_corrupt",
    "unsupported_algorithm",
    "database_restore_required",
    "internal_error",
]);
const FILE_INTEGRITY_COVERAGE_ERRORS = new Set<FileIntegrityCoverageErrorCode>([
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
const FIXED_FILE_PATHS = new Set([
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
]);
const REQUIRED_FIXED_FILE_PATHS = new Set(["/etc/passwd", "/etc/group"]);
const DIRECT_CHILD_ROOTS = [
    "/etc/sudoers.d/",
    "/etc/ssh/sshd_config.d/",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
];
const DIRECTORY_ROOT_PATHS = new Set(DIRECT_CHILD_ROOTS.map(root => root.slice(0, -1)));

function isRecord(value: unknown): value is JsonRecord {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expected: readonly string[]): boolean {
    const actual = Object.keys(value);
    return actual.length === expected.length
        && expected.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function utf8Length(value: string): number {
    return UTF8.encode(value).length;
}

function containsControlCharacter(value: string): boolean {
    return [...value].some(character => {
        const codePoint = character.codePointAt(0) ?? 0;
        return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
    });
}

function isSafeInteger(value: unknown, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER): value is number {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function isTimestamp(value: unknown): value is number {
    return isSafeInteger(value, 0, MAX_TIMESTAMP);
}

function isNullableTimestamp(value: unknown): value is number | null | undefined {
    return value === undefined || value === null || isTimestamp(value);
}

function isBoundedText(value: unknown, maxBytes: number, allowEmpty: boolean): value is string {
    return typeof value === "string"
        && utf8Length(value) <= maxBytes
        && !containsControlCharacter(value)
        && (allowEmpty || value.trim().length > 0);
}

function isMachineIdentifier(value: unknown, maxBytes: number): value is string {
    return isBoundedText(value, maxBytes, false) && MACHINE_IDENTIFIER.test(value);
}

function containsPrivateMarker(value: string): boolean {
    const normalized = value.toLowerCase();
    return PRIVATE_MARKERS.some(marker => normalized.includes(marker));
}

function readAuditEvidenceList(value: unknown): string[] | null {
    if (!Array.isArray(value) || value.length > 128) return null;
    let totalBytes = 0;
    const result: string[] = [];
    for (const item of value) {
        if (!isBoundedText(item, 4096, false) || containsPrivateMarker(item)) return null;
        totalBytes += utf8Length(item);
        if (totalBytes > 4096) return null;
        result.push(item);
    }
    return result;
}

function isCanonicalPort(value: string): boolean {
    if (!/^\d{1,5}$/u.test(value)) return false;
    const port = Number(value);
    return Number.isInteger(port) && port >= 1 && port <= 65_535 && String(port) === value;
}

function isCanonicalCount(value: string): boolean {
    if (!/^\d{1,7}$/u.test(value)) return false;
    const count = Number(value);
    return Number.isSafeInteger(count) && count >= 0 && count <= 1_000_000 && String(count) === value;
}

export function readAuditMetadata(value: unknown): Record<string, string[]> | null {
    if (!isRecord(value)) return null;
    const entries = Object.entries(value);
    if (entries.length > 18) return null;

    let totalBytes = 0;
    const result: Record<string, string[]> = {};
    for (const [key, item] of entries) {
        if (!AUDIT_METADATA_KEYS.has(key) || !Array.isArray(item) || item.length > 128) return null;
        let valueBytes = 0;
        const values: string[] = [];
        for (const raw of item) {
            if (!isBoundedText(raw, 1024, false) || containsPrivateMarker(raw)) return null;
            if (AUDIT_PORT_KEYS.has(key) && !isCanonicalPort(raw)) return null;
            valueBytes += utf8Length(raw);
            if (valueBytes > 4096) return null;
            values.push(raw);
        }
        if (AUDIT_COUNT_KEYS.has(key) && (values.length !== 1 || !isCanonicalCount(values[0]))) {
            return null;
        }
        if (key === "result_kind" && (
            values.length !== 1
            || !AUDIT_RESULT_KINDS.has(values[0] as SecurityAuditResultKind)
        )) return null;
        if (key === "coverage_status" && (values.length !== 1 || values[0] !== "partial")) {
            return null;
        }
        totalBytes += utf8Length(key) + valueBytes;
        if (totalBytes > 48 * 1024) return null;
        result[key] = values;
    }
    return result;
}

function readAuditData(
    value: unknown,
    eventType: "audit.check_failed" | "audit.check_warning",
): AuditSecurityEventEvidenceData<"FAIL" | "WARN"> | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "category",
        "check_id",
        "evidence",
        "metadata",
        "remediation",
        "status",
    ])) return null;

    const evidence = readAuditEvidenceList(value.evidence);
    const metadata = readAuditMetadata(value.metadata);
    const statusIsValid = eventType === "audit.check_failed"
        ? value.status === "FAIL" || value.status === "WARN"
        : value.status === "WARN";
    if (
        !isMachineIdentifier(value.check_id, 128)
        || !isMachineIdentifier(value.category, 64)
        || !statusIsValid
        || !evidence
        || !isBoundedText(value.remediation, 4096, true)
        || containsPrivateMarker(value.remediation)
        || !metadata
        || !auditResultKindMatchesStatus(value.status as "FAIL" | "WARN", metadata)
    ) return null;

    return {
        check_id: value.check_id,
        category: value.category,
        status: value.status as "FAIL" | "WARN",
        evidence,
        remediation: value.remediation,
        metadata,
    };
}

function isCanonicalIpv4(value: string): boolean {
    const parts = value.split(".");
    return parts.length === 4 && parts.every(part => {
        if (!/^\d{1,3}$/u.test(part)) return false;
        const octet = Number(part);
        return octet >= 0 && octet <= 255 && String(octet) === part;
    });
}

function isCanonicalIp(value: string): boolean {
    if (utf8Length(value) > 45 || containsControlCharacter(value)) return false;
    if (!value.includes(":")) return isCanonicalIpv4(value);
    if (value !== value.toLowerCase() || value.includes("%")) return false;
    if (value.startsWith("::ffff:") && value.includes(".")) {
        return isCanonicalIpv4(value.slice("::ffff:".length));
    }
    try {
        return new URL(`http://[${value}]/`).hostname === `[${value}]`;
    } catch {
        return false;
    }
}

function readSshData(value: unknown): SshSecurityEventEvidenceData | null {
    if (!isRecord(value) || !hasExactKeys(value, ["baseline", "ip", "method", "timestamp", "user"])) {
        return null;
    }
    if (
        value.baseline !== "trusted_ips"
        || typeof value.ip !== "string"
        || !isCanonicalIp(value.ip)
        || typeof value.method !== "string"
        || !SSH_METHODS.has(value.method)
        || !isTimestamp(value.timestamp)
        || !isBoundedText(value.user, 64, false)
        || containsPrivateMarker(value.user)
    ) return null;

    return {
        baseline: "trusted_ips",
        ip: value.ip,
        method: value.method as SshSecurityEventEvidenceData["method"],
        timestamp: value.timestamp,
        user: value.user,
    };
}

function readNotificationData(value: unknown): NotificationSecurityEventEvidenceData | null {
    if (!isRecord(value) || !hasExactKeys(value, ["live_limit", "reason", "terminal_limit"])) return null;
    if (value.reason !== "backpressure" || value.live_limit !== 1000 || value.terminal_limit !== 200) {
        return null;
    }
    return { reason: "backpressure", live_limit: 1000, terminal_limit: 200 };
}

function isFrozenLogicalPath(path: string): boolean {
    if (
        utf8Length(path) < 2
        || utf8Length(path) > 1024
        || !path.startsWith("/")
        || path.endsWith("/")
        || containsControlCharacter(path)
    ) return false;
    const components = path.slice(1).split("/");
    if (components.some(component => component.length === 0 || component === "." || component === "..")) {
        return false;
    }
    if (FIXED_FILE_PATHS.has(path) || DIRECTORY_ROOT_PATHS.has(path)) return true;
    return DIRECT_CHILD_ROOTS.some(root => {
        if (!path.startsWith(root)) return false;
        const basename = path.slice(root.length);
        return basename.length > 0
            && utf8Length(basename) <= 255
            && !basename.includes("/")
            && basename !== "."
            && basename !== ".."
            && !containsControlCharacter(basename);
    });
}

function readNullableFileInteger(value: unknown, max: number): number | null | undefined {
    if (value === null) return null;
    return isSafeInteger(value, 0, max) ? value : undefined;
}

function readFileMetadata(
    value: unknown,
    allowPartialRegular: false,
): SensitiveFileCompleteEvidenceMetadata | null;
function readFileMetadata(
    value: unknown,
    allowPartialRegular: true,
): SensitiveFileObservedEvidenceMetadata | null;
function readFileMetadata(
    value: unknown,
    allowPartialRegular: boolean,
): SensitiveFileCompleteEvidenceMetadata | SensitiveFileObservedEvidenceMetadata | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "gid",
        "mode",
        "mtime_unix_seconds",
        "size_bytes",
        "state",
        "uid",
    ])) return null;

    const sizeBytes = readNullableFileInteger(value.size_bytes, Number.MAX_SAFE_INTEGER);
    const mtime = readNullableFileInteger(value.mtime_unix_seconds, MAX_TIMESTAMP);
    const mode = readNullableFileInteger(value.mode, 0o7777);
    const uid = readNullableFileInteger(value.uid, 0xffff_ffff);
    const gid = readNullableFileInteger(value.gid, 0xffff_ffff);
    if (
        sizeBytes === undefined
        || mtime === undefined
        || mode === undefined
        || uid === undefined
        || gid === undefined
    ) return null;

    if (value.state === "absent") {
        if ([sizeBytes, mtime, mode, uid, gid].some(item => item !== null)) return null;
        return {
            state: "absent",
            size_bytes: null,
            mtime_unix_seconds: null,
            mode: null,
            uid: null,
            gid: null,
        };
    }
    if (value.state === "directory") {
        if (allowPartialRegular) return null;
        if (sizeBytes !== null || mtime !== null || mode === null || uid === null || gid === null) {
            return null;
        }
        return {
            state: "directory",
            size_bytes: null,
            mtime_unix_seconds: null,
            mode,
            uid,
            gid,
        };
    }
    if (value.state !== "regular") return null;
    if (!allowPartialRegular && [sizeBytes, mtime, mode, uid, gid].some(item => item === null)) {
        return null;
    }

    return {
        state: "regular",
        size_bytes: sizeBytes,
        mtime_unix_seconds: mtime,
        mode,
        uid,
        gid,
    } as SensitiveFileObservedEvidenceMetadata;
}

function fileMetadataMatchesLogicalPath(
    path: string,
    baseline: SensitiveFileCompleteEvidenceMetadata,
    observed: SensitiveFileCompleteEvidenceMetadata | SensitiveFileObservedEvidenceMetadata,
    changeKinds: SensitiveFileChangeKind[],
    observationFailed: boolean,
): boolean {
    const baselineDirectory = baseline.state === "directory";
    const observedDirectory = observed.state === "directory";
    const directoryRoot = DIRECTORY_ROOT_PATHS.has(path);
    const baselineMatchesTarget = directoryRoot
        ? baselineDirectory || baseline.state === "absent"
        : REQUIRED_FIXED_FILE_PATHS.has(path)
            ? baseline.state === "regular"
            : !baselineDirectory;
    if (!baselineMatchesTarget) return false;

    const has = (kind: SensitiveFileChangeKind) => changeKinds.includes(kind);
    const ownerChangeIsProven = baseline.state !== "absent"
        && observed.state !== "absent"
        && ((baseline.uid !== null
                && observed.uid !== null
                && baseline.uid !== observed.uid)
            || (baseline.gid !== null
                && observed.gid !== null
                && baseline.gid !== observed.gid));
    const permissionChangeIsProven = baseline.state !== "absent"
        && observed.state !== "absent"
        && baseline.mode !== null
        && observed.mode !== null
        && baseline.mode !== observed.mode;
    if (observationFailed) {
        return !directoryRoot
            && !observedDirectory
            && has("unreadable")
            && !has("added")
            && !has("removed")
            && !has("type_changed")
            && !has("content_changed")
            && has("owner_changed") === ownerChangeIsProven
            && has("permissions_changed") === permissionChangeIsProven;
    }
    if (has("unreadable")) return false;

    const baselinePresent = baseline.state !== "absent";
    const observedPresent = observed.state !== "absent";
    const observedHasWrongTargetType = directoryRoot
        ? observed.state === "regular"
        : observedDirectory;
    const contentChangeIsValid = !has("content_changed")
        || (baseline.state === "regular" && observed.state === "regular");
    const regularSizeChanged = baseline.state === "regular"
        && observed.state === "regular"
        && baseline.size_bytes !== observed.size_bytes;
    return has("added") === (!baselinePresent && observedPresent)
        && has("removed") === (baselinePresent && !observedPresent)
        && has("type_changed") === observedHasWrongTargetType
        && has("owner_changed") === ownerChangeIsProven
        && has("permissions_changed") === permissionChangeIsProven
        && contentChangeIsValid
        && (!regularSizeChanged || has("content_changed"));
}

function readFileData(value: unknown): SensitiveFileChangedEvidenceData | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "baseline_generation",
        "baseline_metadata",
        "change_kinds",
        "logical_path",
        "observation_error",
        "observed_at",
        "observed_generation",
        "observed_metadata",
        "path_id",
    ])) return null;
    const changeKinds = Array.isArray(value.change_kinds)
        && value.change_kinds.every(
            (item): item is SensitiveFileChangeKind =>
                typeof item === "string" && FILE_CHANGE_KINDS.has(item as SensitiveFileChangeKind),
        )
        ? value.change_kinds
        : null;
    if (
        typeof value.path_id !== "string"
        || !PATH_ID.test(value.path_id)
        || typeof value.logical_path !== "string"
        || !isFrozenLogicalPath(value.logical_path)
        || !changeKinds
        || changeKinds.length < 1
        || changeKinds.length > 7
        || !changeKinds.every((item, index) => index === 0 || changeKinds[index - 1] < item)
        || !isSafeInteger(value.baseline_generation, 0)
        || !isSafeInteger(value.observed_generation, 0)
        || !isTimestamp(value.observed_at)
        || !(value.observation_error === null
            || (typeof value.observation_error === "string"
                && FILE_OBSERVATION_ERRORS.has(value.observation_error as SensitiveFileObservationError)))
    ) return null;

    const baselineMetadata = readFileMetadata(value.baseline_metadata, false);
    if (!baselineMetadata) return null;
    const base = {
        path_id: value.path_id,
        logical_path: value.logical_path,
        change_kinds: [...changeKinds],
        baseline_generation: value.baseline_generation,
        observed_generation: value.observed_generation,
        baseline_metadata: baselineMetadata,
        observed_at: value.observed_at,
    };

    if (value.observation_error === null) {
        const observedMetadata = readFileMetadata(value.observed_metadata, false);
        return observedMetadata
            && fileMetadataMatchesLogicalPath(
                value.logical_path,
                baselineMetadata,
                observedMetadata,
                changeKinds,
                false,
            )
            ? { ...base, observed_metadata: observedMetadata, observation_error: null }
            : null;
    }
    const observedMetadata = readFileMetadata(value.observed_metadata, true);
    return observedMetadata
        && fileMetadataMatchesLogicalPath(
            value.logical_path,
            baselineMetadata,
            observedMetadata,
            changeKinds,
            true,
        )
        ? {
            ...base,
            observed_metadata: observedMetadata,
            observation_error: value.observation_error as SensitiveFileObservationError,
        }
        : null;
}

function readIntegrityErrorCounts(value: unknown): FileIntegrityErrorCount[] | null {
    if (!Array.isArray(value) || value.length > 24) return null;

    const result: FileIntegrityErrorCount[] = [];
    let previousCode: string | null = null;
    let total = 0;
    for (const item of value) {
        if (!isRecord(item) || !hasExactKeys(item, ["code", "count"])) return null;
        if (
            typeof item.code !== "string"
            || !FILE_INTEGRITY_COVERAGE_ERRORS.has(item.code as FileIntegrityCoverageErrorCode)
            || !isSafeInteger(item.count, 1, 256)
            || (previousCode !== null && previousCode >= item.code)
        ) return null;

        total += item.count;
        if (total > 256) return null;
        previousCode = item.code;
        result.push({ code: item.code as FileIntegrityCoverageErrorCode, count: item.count });
    }
    return result;
}

function readIntegrityCoverageData(value: unknown): FileIntegrityCoverageDegradedEvidenceData | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "baseline_generation",
        "degraded_reason",
        "drift_file_count",
        "error_counts",
        "observation_complete",
        "observed_at",
        "observed_generation",
        "state_revision",
        "tracked_file_count",
        "unavailable_target_count",
    ])) return null;

    const errorCounts = readIntegrityErrorCounts(value.error_counts);
    if (
        typeof value.degraded_reason !== "string"
        || !FILE_INTEGRITY_DEGRADED_REASONS.has(value.degraded_reason as FileIntegrityDegradedReason)
        || !isSafeInteger(value.state_revision, 0)
        || !isSafeInteger(value.baseline_generation, 0)
        || !isSafeInteger(value.observed_generation, 0)
        || typeof value.observation_complete !== "boolean"
        || !isTimestamp(value.observed_at)
        || !isSafeInteger(value.tracked_file_count, 0, 256)
        || !isSafeInteger(value.drift_file_count, 0, 256)
        || value.drift_file_count > value.tracked_file_count
        || !isSafeInteger(value.unavailable_target_count, 0, 256)
        || errorCounts === null
    ) return null;

    return {
        degraded_reason: value.degraded_reason as FileIntegrityDegradedReason,
        state_revision: value.state_revision,
        baseline_generation: value.baseline_generation,
        observed_generation: value.observed_generation,
        observation_complete: value.observation_complete,
        observed_at: value.observed_at,
        tracked_file_count: value.tracked_file_count,
        drift_file_count: value.drift_file_count,
        unavailable_target_count: value.unavailable_target_count,
        error_counts: errorCounts,
    };
}

function readIntegrityReenrolledData(value: unknown): FileIntegrityBaselineReenrolledEvidenceData | null {
    if (!isRecord(value) || !hasExactKeys(value, [
        "new_baseline_generation",
        "observed_generation",
        "old_baseline_generation",
        "reason",
        "reenrolled_at",
        "state_revision",
    ])) return null;
    if (
        value.reason !== "baseline_corrupt"
        || !isSafeInteger(value.old_baseline_generation, 1)
        || !isSafeInteger(value.new_baseline_generation, 1)
        || !isSafeInteger(value.state_revision, 0)
        || !isSafeInteger(value.observed_generation, 1)
        || !isTimestamp(value.reenrolled_at)
    ) return null;

    return {
        reason: "baseline_corrupt",
        old_baseline_generation: value.old_baseline_generation,
        new_baseline_generation: value.new_baseline_generation,
        state_revision: value.state_revision,
        observed_generation: value.observed_generation,
        reenrolled_at: value.reenrolled_at,
    };
}

function fallbackEvidence(raw: unknown, eventType: string): SecurityEventEvidence {
    const schemaVersion = isRecord(raw)
        && isSafeInteger(raw.schema_version, 1, 65_535)
        ? raw.schema_version
        : 1;
    return {
        schema_version: schemaVersion,
        kind: eventType,
        data: null,
        error_code: "invalid_stored_payload",
    };
}

export function decodeSecurityEventEvidence(raw: unknown, eventType: string): SecurityEventEvidence {
    if (!isRecord(raw) || !hasExactKeys(raw, ["data", "error_code", "kind", "schema_version"])) {
        return fallbackEvidence(raw, eventType);
    }
    if (raw.kind !== eventType) return fallbackEvidence(raw, eventType);

    if (
        isSafeInteger(raw.schema_version, 1, 65_535)
        && raw.data === null
        && typeof raw.error_code === "string"
        && EVIDENCE_ERROR_CODES.has(raw.error_code)
    ) {
        return {
            schema_version: raw.schema_version,
            kind: eventType,
            data: null,
            error_code: raw.error_code as "unsupported_schema_version" | "invalid_stored_payload",
        };
    }
    if (raw.schema_version !== 1 || raw.error_code !== null) return fallbackEvidence(raw, eventType);

    if (eventType === "audit.check_failed") {
        const data = readAuditData(raw.data, eventType);
        return data
            ? { schema_version: 1, kind: eventType, data, error_code: null }
            : fallbackEvidence(raw, eventType);
    }
    if (eventType === "audit.check_warning") {
        const data = readAuditData(raw.data, eventType);
        return data
            ? {
                schema_version: 1,
                kind: eventType,
                data: data as AuditSecurityEventEvidenceData<"WARN">,
                error_code: null,
            }
            : fallbackEvidence(raw, eventType);
    }
    if (eventType === "ssh.untrusted_source_ip") {
        const data = readSshData(raw.data);
        return data
            ? { schema_version: 1, kind: eventType, data, error_code: null }
            : fallbackEvidence(raw, eventType);
    }
    if (eventType === "notification.delivery_degraded") {
        const data = readNotificationData(raw.data);
        return data
            ? { schema_version: 1, kind: eventType, data, error_code: null }
            : fallbackEvidence(raw, eventType);
    }
    if (eventType === "file.sensitive_changed") {
        const data = readFileData(raw.data);
        return data
            ? { schema_version: 1, kind: eventType, data, error_code: null }
            : fallbackEvidence(raw, eventType);
    }
    if (eventType === "file.integrity_coverage_degraded") {
        const data = readIntegrityCoverageData(raw.data);
        return data
            ? { schema_version: 1, kind: eventType, data, error_code: null }
            : fallbackEvidence(raw, eventType);
    }
    if (eventType === "file.integrity_baseline_reenrolled") {
        const data = readIntegrityReenrolledData(raw.data);
        return data
            ? { schema_version: 1, kind: eventType, data, error_code: null }
            : fallbackEvidence(raw, eventType);
    }
    return fallbackEvidence(raw, eventType);
}

function isNullableDeliveryStatus(value: unknown): value is NotificationDeliveryStatus | null | undefined {
    return value === undefined
        || value === null
        || (typeof value === "string" && NOTIFICATION_DELIVERY_STATUSES.has(value as NotificationDeliveryStatus));
}

function isNullableDeliveryErrorCode(value: unknown): value is NotificationDeliveryErrorCode | null | undefined {
    return value === undefined
        || value === null
        || (typeof value === "string"
            && NOTIFICATION_DELIVERY_ERROR_CODES.has(value as NotificationDeliveryErrorCode));
}

export function decodeSecurityEvent(raw: unknown): SecurityEvent | null {
    if (
        !isRecord(raw)
        || !isSafeInteger(raw.id, 1)
        || !isMachineIdentifier(raw.event_type, 128)
        || !isBoundedText(raw.event_key, 255, false)
        || !isBoundedText(raw.title, 4096, false)
        || !isBoundedText(raw.message, 16 * 1024, true)
        || typeof raw.severity !== "string"
        || !SECURITY_EVENT_SEVERITIES.has(raw.severity)
        || typeof raw.evidence_json !== "string"
        || utf8Length(raw.evidence_json) > MAX_EVIDENCE_BYTES
        || typeof raw.status !== "string"
        || !SECURITY_EVENT_STATUSES.has(raw.status)
        || !isTimestamp(raw.first_seen)
        || !isTimestamp(raw.last_seen)
        || raw.first_seen > raw.last_seen
        || !isNullableTimestamp(raw.acknowledged_at)
        || !isNullableTimestamp(raw.resolved_at)
        || !(raw.notification_delivery_attempts === undefined
            || raw.notification_delivery_attempts === null
            || isSafeInteger(raw.notification_delivery_attempts, 0, 1_000_000))
        || !isNullableTimestamp(raw.notification_delivery_updated_at)
        || !isNullableDeliveryStatus(raw.notification_delivery_status)
        || !isNullableDeliveryErrorCode(raw.notification_delivery_error_code)
    ) return null;

    const event: SecurityEvent = {
        id: raw.id,
        event_key: raw.event_key,
        event_type: raw.event_type,
        severity: raw.severity as SecurityEvent["severity"],
        title: raw.title,
        message: raw.message,
        evidence: decodeSecurityEventEvidence(raw.evidence, raw.event_type),
        evidence_json: raw.evidence_json,
        status: raw.status as SecurityEvent["status"],
        first_seen: raw.first_seen,
        last_seen: raw.last_seen,
        acknowledged_at: raw.acknowledged_at ?? null,
        resolved_at: raw.resolved_at ?? null,
        notification_delivery_status: raw.notification_delivery_status ?? null,
        notification_delivery_attempts: raw.notification_delivery_attempts ?? null,
        notification_delivery_updated_at: raw.notification_delivery_updated_at ?? null,
        notification_delivery_error_code: raw.notification_delivery_error_code ?? null,
    };
    return validIntegrityEventContext(event) ? event : null;
}

function hasNoNotificationState(event: SecurityEvent): boolean {
    return event.notification_delivery_status === null
        && event.notification_delivery_attempts === null
        && event.notification_delivery_updated_at === null
        && event.notification_delivery_error_code === null;
}

function hasValidIntegrityStatusTimestamps(event: SecurityEvent): boolean {
    if (event.status === "open") {
        return event.acknowledged_at === null && event.resolved_at === null;
    }
    if (event.status === "acknowledged") {
        return event.acknowledged_at !== null && event.resolved_at === null;
    }
    return event.resolved_at !== null;
}

function validIntegrityEventContext(event: SecurityEvent): boolean {
    if (event.evidence.error_code !== null) return true;

    if (event.evidence.kind === "file.sensitive_changed") {
        return event.event_key === `file:sensitive_changed:${event.evidence.data.path_id}`
            && event.severity === "high"
            && hasValidIntegrityStatusTimestamps(event);
    }
    if (event.evidence.kind === "file.integrity_coverage_degraded") {
        const highSeverity = HIGH_INTEGRITY_DEGRADED_REASONS.has(event.evidence.data.degraded_reason);
        return event.event_key === "file:integrity_coverage_degraded"
            && event.severity === (highSeverity ? "high" : "medium")
            && hasValidIntegrityStatusTimestamps(event)
            && hasNoNotificationState(event);
    }
    if (event.evidence.kind === "file.integrity_baseline_reenrolled") {
        const timestamp = event.evidence.data.reenrolled_at;
        return event.event_key
                === `file:integrity_baseline_reenrolled:${event.evidence.data.state_revision}`
            && event.severity === "info"
            && event.status === "resolved"
            && event.first_seen === timestamp
            && event.last_seen === timestamp
            && event.acknowledged_at === null
            && event.resolved_at === timestamp
            && hasNoNotificationState(event);
    }
    return true;
}
