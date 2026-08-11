import type { SecurityAuditResultKind } from "@/types";

export type SecurityCheckStatus = "PASS" | "FAIL" | "WARN";

const CHECK_NAME_KEYS: Readonly<Record<string, string>> = {
    "ssh.root_login": "security.audit_checks.ssh_root_login",
    "ssh.password_auth": "security.audit_checks.ssh_password_auth",
    "firewall.ufw": "security.audit_checks.firewall_ufw",
    "docker.socket_permissions": "security.audit_checks.docker_socket_permissions",
    "system.disk_encryption": "security.audit_checks.system_disk_encryption",
    "intrusion.fail2ban": "security.audit_checks.intrusion_fail2ban",
    "network.listening_ports": "security.audit_checks.network_listening_ports",
    "docker.tcp_api": "security.audit_checks.docker_tcp_api",
    "docker.container_hardening": "security.audit_checks.docker_container_hardening",
    "runtime.docker_control_access": "security.audit_checks.runtime_docker_control_access",
};

export function isAggregateAuditCheck(checkId: string): boolean {
    return checkId === "audit.collection";
}

export function auditCheckNameKey(checkId: string): string | null {
    return CHECK_NAME_KEYS[checkId] ?? null;
}

export function auditResultKindMatchesStatus(
    status: SecurityCheckStatus,
    metadata: Readonly<Record<string, string[]>>,
): boolean {
    const coverageStatus = metadata.coverage_status;
    if (coverageStatus !== undefined && (
        coverageStatus.length !== 1
        || coverageStatus[0] !== "partial"
        || status === "PASS"
    )) return false;

    const declared = metadata.result_kind;
    if (declared === undefined) return true;
    if (declared.length !== 1) return false;

    if (status === "PASS") return declared[0] === "pass";
    if (status === "FAIL") return declared[0] === "finding";
    return declared[0] === "finding"
        || declared[0] === "recommendation"
        || declared[0] === "unverified"
        || declared[0] === "coverage";
}

export function classifySecurityResult(
    status: SecurityCheckStatus,
    metadata: Readonly<Record<string, string[]>>,
): SecurityAuditResultKind {
    const declared = metadata.result_kind;
    if (declared?.length === 1) {
        return declared[0] as SecurityAuditResultKind;
    }

    if (status === "PASS") return "pass";
    if (status === "FAIL") return "finding";

    // Older servers did not distinguish recommendations from incomplete
    // coverage. A legacy WARN therefore stays fail-safe until a typed snapshot
    // supplies result_kind instead of being promoted to a verified result.
    return "unverified";
}
