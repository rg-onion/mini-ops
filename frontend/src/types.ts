export interface SystemStats {
    cpu_usage: number;
    memory_used: number;
    memory_total: number;
    disk_used: number;
    disk_total: number;
    timestamp: number;
}

export interface ContainerInfo {
    id: string;
    name: string;
    image: string;
    status: string;
    state: string;
    ports: string;
}

export interface AuditSecurityEventEvidenceData<Status extends "FAIL" | "WARN"> {
    check_id: string;
    category: string;
    status: Status;
    evidence: string[];
    remediation: string;
    metadata: Record<string, string[]>;
}

export interface SshSecurityEventEvidenceData {
    user: string;
    ip: string;
    method: "ssh" | "password" | "publickey" | "keyboard-interactive" | "unknown";
    timestamp: number;
    baseline: "trusted_ips";
}

export interface NotificationSecurityEventEvidenceData {
    reason: "backpressure";
    live_limit: 1000;
    terminal_limit: 200;
}

export type SensitiveFileChangeKind =
    | "added"
    | "content_changed"
    | "owner_changed"
    | "permissions_changed"
    | "removed"
    | "type_changed"
    | "unreadable";

export type SensitiveFileObservationError =
    | "permission_denied"
    | "symlink"
    | "not_regular"
    | "file_too_large"
    | "changed_during_read"
    | "vanished_during_scan"
    | "io_error";

export type FileIntegrityStatusValue = "disabled" | "initializing" | "healthy" | "drift" | "degraded";

export type FileIntegrityCoverageStatus = "disabled" | "initializing" | "full" | "degraded";

export type FileIntegrityDegradedReason =
    | "coverage_unavailable"
    | "limit_exceeded"
    | "deadline_exceeded"
    | "baseline_corrupt"
    | "unsupported_algorithm"
    | "database_restore_required"
    | "internal_error";

export type FileIntegrityCoverageErrorCode =
    | "permission_denied"
    | "symlink"
    | "not_regular"
    | "file_too_large"
    | "changed_during_read"
    | "vanished_during_scan"
    | "io_error"
    | "tracked_file_limit"
    | "scan_byte_limit"
    | "deadline_exceeded"
    | "directory_unreadable"
    | "path_not_utf8"
    | "path_too_long"
    | "network_filesystem"
    | "filesystem_unclassified"
    | "untrusted_new_coverage"
    | "no_observable_targets";

export interface FileIntegrityErrorCount {
    code: FileIntegrityCoverageErrorCode;
    count: number;
}

export interface FileIntegrityCoverage {
    status: FileIntegrityCoverageStatus;
    unavailable_target_count: number;
    error_counts: FileIntegrityErrorCount[];
}

export interface FileIntegrityStatus {
    schema_version: 1;
    status: FileIntegrityStatusValue;
    state_revision: number | null;
    baseline_generation: number | null;
    observed_generation: number | null;
    observation_complete: boolean;
    trust_available: boolean;
    re_enroll_available: boolean;
    degraded_reason: FileIntegrityDegradedReason | null;
    last_scan_at: number | null;
    tracked_file_count: number;
    drift_file_count: number;
    coverage: FileIntegrityCoverage;
}

export interface FileIntegrityCoverageDegradedEvidenceData {
    degraded_reason: FileIntegrityDegradedReason;
    state_revision: number;
    baseline_generation: number;
    observed_generation: number;
    observation_complete: boolean;
    observed_at: number;
    tracked_file_count: number;
    drift_file_count: number;
    unavailable_target_count: number;
    error_counts: FileIntegrityErrorCount[];
}

export interface FileIntegrityBaselineReenrolledEvidenceData {
    reason: "baseline_corrupt";
    old_baseline_generation: number;
    new_baseline_generation: number;
    state_revision: number;
    observed_generation: number;
    reenrolled_at: number;
}

export interface FileIntegrityTrustResult {
    result: "trusted";
    status: "healthy";
    state_revision: number;
    baseline_generation: number;
    observed_generation: number;
    trusted_at: number;
    resolved_event_count: number;
}

export interface FileIntegrityReenrollResult {
    result: "reenrolled";
    status: "healthy";
    state_revision: number;
    baseline_generation: number;
    observed_generation: number;
    reenrolled_at: number;
    resolved_event_count: number;
}

export type FileIntegrityActionErrorCode =
    | "invalid_request"
    | "stale_generation"
    | "not_initialized"
    | "no_drift"
    | "observation_not_trustable"
    | "feature_disabled"
    | "recovery_not_required"
    | "unsupported_algorithm"
    | "internal_error";

export interface FileIntegrityActionErrorEnvelope {
    error: {
        code: FileIntegrityActionErrorCode;
        status: FileIntegrityStatusValue | null;
        state_revision: number | null;
        baseline_generation: number | null;
        observed_generation: number | null;
    };
}

export type SensitiveFileCompleteEvidenceMetadata =
    | {
        state: "absent";
        size_bytes: null;
        mtime_unix_seconds: null;
        mode: null;
        uid: null;
        gid: null;
    }
    | {
        state: "regular";
        size_bytes: number;
        mtime_unix_seconds: number;
        mode: number;
        uid: number;
        gid: number;
    }
    | {
        state: "directory";
        size_bytes: null;
        mtime_unix_seconds: null;
        mode: number;
        uid: number;
        gid: number;
    };

export type SensitiveFileObservedEvidenceMetadata =
    | Extract<SensitiveFileCompleteEvidenceMetadata, { state: "absent" }>
    | {
        state: "regular";
        size_bytes: number | null;
        mtime_unix_seconds: number | null;
        mode: number | null;
        uid: number | null;
        gid: number | null;
    };

interface SensitiveFileChangedEvidenceDataBase {
    path_id: string;
    logical_path: string;
    change_kinds: SensitiveFileChangeKind[];
    baseline_generation: number;
    observed_generation: number;
    baseline_metadata: SensitiveFileCompleteEvidenceMetadata;
    observed_at: number;
}

export type SensitiveFileChangedEvidenceData = SensitiveFileChangedEvidenceDataBase & (
    | {
        observed_metadata: SensitiveFileCompleteEvidenceMetadata;
        observation_error: null;
    }
    | {
        observed_metadata: SensitiveFileObservedEvidenceMetadata;
        observation_error: SensitiveFileObservationError;
    }
);

export type KnownSecurityEventEvidence =
    | {
        schema_version: 1;
        kind: "audit.check_failed";
        data: AuditSecurityEventEvidenceData<"FAIL" | "WARN">;
        error_code: null;
    }
    | {
        schema_version: 1;
        kind: "audit.check_warning";
        data: AuditSecurityEventEvidenceData<"WARN">;
        error_code: null;
    }
    | {
        schema_version: 1;
        kind: "ssh.untrusted_source_ip";
        data: SshSecurityEventEvidenceData;
        error_code: null;
    }
    | {
        schema_version: 1;
        kind: "notification.delivery_degraded";
        data: NotificationSecurityEventEvidenceData;
        error_code: null;
    }
    | {
        schema_version: 1;
        kind: "file.sensitive_changed";
        data: SensitiveFileChangedEvidenceData;
        error_code: null;
    }
    | {
        schema_version: 1;
        kind: "file.integrity_coverage_degraded";
        data: FileIntegrityCoverageDegradedEvidenceData;
        error_code: null;
    }
    | {
        schema_version: 1;
        kind: "file.integrity_baseline_reenrolled";
        data: FileIntegrityBaselineReenrolledEvidenceData;
        error_code: null;
    };

export type UnavailableSecurityEventEvidence = {
    schema_version: number;
    kind: string;
    data: null;
    error_code: "unsupported_schema_version" | "invalid_stored_payload";
};

export type SecurityEventEvidence = KnownSecurityEventEvidence | UnavailableSecurityEventEvidence;

export type NotificationDeliveryStatus =
    | "pending"
    | "sending"
    | "sent"
    | "failed"
    | "disabled"
    | "suppressed";

export type NotificationDeliveryErrorCode =
    | "dns"
    | "connect_timeout"
    | "request_timeout"
    | "transport"
    | "http_4xx"
    | "http_5xx"
    | "response_too_large"
    | "invalid_response"
    | "provider_rejected"
    | "lease_expired"
    | "retention_expired";

export interface SecurityEvent {
    id: number;
    event_key: string;
    event_type: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    message: string;
    evidence: SecurityEventEvidence;
    evidence_json: string;
    status: "open" | "acknowledged" | "resolved";
    first_seen: number;
    last_seen: number;
    acknowledged_at: number | null;
    resolved_at: number | null;
    notification_delivery_status: NotificationDeliveryStatus | null;
    notification_delivery_attempts: number | null;
    notification_delivery_updated_at: number | null;
    notification_delivery_error_code: NotificationDeliveryErrorCode | null;
}
