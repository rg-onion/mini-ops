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
    | "tracked_file_limit"
    | "scan_byte_limit"
    | "deadline_exceeded"
    | "changed_during_read"
    | "vanished_during_scan"
    | "directory_unreadable"
    | "path_not_utf8"
    | "path_too_long"
    | "io_error";

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
