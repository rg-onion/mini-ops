use bollard::Docker;
use bollard::models::{ContainerInspectResponse, HostConfigCgroupnsModeEnum, MountPointTypeEnum};
use bollard::query_parameters::{
    InspectContainerOptions, ListContainersOptions, LogsOptions, RestartContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::AsyncReadExt;

const MAX_DOCKER_AUDIT_CONTAINERS: usize = 256;
const MAX_DOCKER_AUDIT_CAPABILITIES: usize = 256;
const MAX_DOCKER_AUDIT_MOUNTS: usize = 256;
const MAX_DOCKER_AUDIT_DEVICE_ITEMS: usize = 256;
const MAX_DOCKER_SECURITY_OPTIONS: usize = 64;
const MAX_DOCKER_DAEMON_SECURITY_OPTIONS: usize = 64;
const MAX_DOCKER_SYSTEM_PATHS: usize = 64;
const MAX_DOCKER_SECURITY_RISKS: usize = 128;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String, // running, exited, etc.
    pub ports: String,
}

#[derive(Debug)]
struct AuditContainerIdentity {
    id: String,
    fallback_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerSecurityRisk {
    pub severity: String,
    pub finding: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DockerSecurityAuditOutcome {
    pub risks: Vec<DockerSecurityRisk>,
    pub incomplete_reasons: Vec<DockerSecurityIncompleteReason>,
}

impl DockerSecurityAuditOutcome {
    fn mark_incomplete(&mut self, reason: DockerSecurityIncompleteReason) {
        if !self.incomplete_reasons.contains(&reason) {
            self.incomplete_reasons.push(reason);
        }
    }

    fn merge(&mut self, mut other: Self) {
        self.risks.append(&mut other.risks);
        self.enforce_risk_limit();
        for reason in other.incomplete_reasons {
            self.mark_incomplete(reason);
        }
    }

    fn enforce_risk_limit(&mut self) {
        if self.risks.len() > MAX_DOCKER_SECURITY_RISKS {
            self.risks.sort_by(|left, right| {
                docker_risk_priority(right)
                    .cmp(&docker_risk_priority(left))
                    .then_with(|| left.finding.cmp(&right.finding))
                    .then_with(|| left.evidence.cmp(&right.evidence))
            });
            self.risks.truncate(MAX_DOCKER_SECURITY_RISKS);
            self.mark_incomplete(DockerSecurityIncompleteReason::RiskLimitExceeded);
        }
    }
}

fn docker_risk_priority(risk: &DockerSecurityRisk) -> u8 {
    match risk.severity.as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerSecurityIncompleteReason {
    ListContainersUnavailable,
    DockerInfoUnavailable,
    DockerAuditDeadlineExceeded,
    MissingDaemonSecurityOptions,
    InvalidDaemonSecurityOption,
    DuplicateDaemonSecurityOption,
    ConflictingDaemonSecurityOption,
    InspectContainerUnavailable,
    MissingHostConfig,
    MissingMounts,
    MissingPrivileged,
    MissingNetworkMode,
    InvalidNetworkMode,
    MissingPidMode,
    InvalidPidMode,
    MissingIpcMode,
    InvalidIpcMode,
    MissingUsernsMode,
    InvalidUsernsMode,
    MissingUtsMode,
    InvalidUtsMode,
    MissingCgroupnsMode,
    AmbiguousCgroupnsMode,
    MissingAppArmorProfile,
    InvalidAppArmorProfile,
    MissingSelinuxProcessLabel,
    InvalidSelinuxProcessLabel,
    UnclassifiedSelinuxProcessLabel,
    SelinuxEnforcementUnavailable,
    InvalidSelinuxEnforcement,
    IncompleteMountType,
    IncompleteBindSource,
    IncompleteBindDestination,
    IncompleteBindWritable,
    MalformedSecurityOption,
    DuplicateSecurityOption,
    ConflictingSecurityOption,
    ConflictingAppArmorFacts,
    InvalidContainerIdentity,
    ContainerLimitExceeded,
    CapabilityLimitExceeded,
    MountLimitExceeded,
    SecurityOptionLimitExceeded,
    DaemonSecurityOptionLimitExceeded,
    RiskLimitExceeded,
    InvalidCapability,
    DeviceLimitExceeded,
    UnclassifiedSecurityProfile,
    MissingMaskedPaths,
    MissingReadonlyPaths,
    InvalidSystemPaths,
}

impl DockerSecurityIncompleteReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::ListContainersUnavailable => "list_containers_unavailable",
            Self::DockerInfoUnavailable => "docker_info_unavailable",
            Self::DockerAuditDeadlineExceeded => "docker_audit_deadline_exceeded",
            Self::MissingDaemonSecurityOptions => "missing_daemon_security_options",
            Self::InvalidDaemonSecurityOption => "invalid_daemon_security_option",
            Self::DuplicateDaemonSecurityOption => "duplicate_daemon_security_option",
            Self::ConflictingDaemonSecurityOption => "conflicting_daemon_security_option",
            Self::InspectContainerUnavailable => "inspect_container_unavailable",
            Self::MissingHostConfig => "missing_host_config",
            Self::MissingMounts => "missing_mounts",
            Self::MissingPrivileged => "missing_privileged",
            Self::MissingNetworkMode => "missing_network_mode",
            Self::InvalidNetworkMode => "invalid_network_mode",
            Self::MissingPidMode => "missing_pid_mode",
            Self::InvalidPidMode => "invalid_pid_mode",
            Self::MissingIpcMode => "missing_ipc_mode",
            Self::InvalidIpcMode => "invalid_ipc_mode",
            Self::MissingUsernsMode => "missing_userns_mode",
            Self::InvalidUsernsMode => "invalid_userns_mode",
            Self::MissingUtsMode => "missing_uts_mode",
            Self::InvalidUtsMode => "invalid_uts_mode",
            Self::MissingCgroupnsMode => "missing_cgroupns_mode",
            Self::AmbiguousCgroupnsMode => "ambiguous_cgroupns_mode",
            Self::MissingAppArmorProfile => "missing_apparmor_profile",
            Self::InvalidAppArmorProfile => "invalid_apparmor_profile",
            Self::MissingSelinuxProcessLabel => "missing_selinux_process_label",
            Self::InvalidSelinuxProcessLabel => "invalid_selinux_process_label",
            Self::UnclassifiedSelinuxProcessLabel => "unclassified_selinux_process_label",
            Self::SelinuxEnforcementUnavailable => "selinux_enforcement_unavailable",
            Self::InvalidSelinuxEnforcement => "invalid_selinux_enforcement",
            Self::IncompleteMountType => "incomplete_mount_type",
            Self::IncompleteBindSource => "incomplete_bind_source",
            Self::IncompleteBindDestination => "incomplete_bind_destination",
            Self::IncompleteBindWritable => "incomplete_bind_writable",
            Self::MalformedSecurityOption => "malformed_security_option",
            Self::DuplicateSecurityOption => "duplicate_security_option",
            Self::ConflictingSecurityOption => "conflicting_security_option",
            Self::ConflictingAppArmorFacts => "conflicting_apparmor_facts",
            Self::InvalidContainerIdentity => "invalid_container_identity",
            Self::ContainerLimitExceeded => "container_limit_exceeded",
            Self::CapabilityLimitExceeded => "capability_limit_exceeded",
            Self::MountLimitExceeded => "mount_limit_exceeded",
            Self::SecurityOptionLimitExceeded => "security_option_limit_exceeded",
            Self::DaemonSecurityOptionLimitExceeded => "daemon_security_option_limit_exceeded",
            Self::RiskLimitExceeded => "risk_limit_exceeded",
            Self::InvalidCapability => "invalid_capability",
            Self::DeviceLimitExceeded => "device_limit_exceeded",
            Self::UnclassifiedSecurityProfile => "unclassified_security_profile",
            Self::MissingMaskedPaths => "missing_masked_paths",
            Self::MissingReadonlyPaths => "missing_readonly_paths",
            Self::InvalidSystemPaths => "invalid_system_paths",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityFact {
    Enabled,
    Disabled,
    Unknown(DockerSecurityIncompleteReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DockerDaemonSecurityFacts {
    seccomp: SecurityFact,
    no_new_privileges: SecurityFact,
    userns: SecurityFact,
    selinux: SecurityFact,
    seccomp_unconfined_seen: bool,
    option_limit_exceeded: bool,
}

impl DockerDaemonSecurityFacts {
    fn unknown(reason: DockerSecurityIncompleteReason) -> Self {
        Self {
            seccomp: SecurityFact::Unknown(reason),
            no_new_privileges: SecurityFact::Unknown(reason),
            userns: SecurityFact::Unknown(reason),
            selinux: SecurityFact::Unknown(reason),
            seccomp_unconfined_seen: false,
            option_limit_exceeded: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SecurityProfileOverride {
    KnownConfined(String),
    Unconfined,
    Unclassified(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum OverrideState<T> {
    #[default]
    Absent,
    Value(T),
    Invalid,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedSecurityOptions {
    seccomp: OverrideState<SecurityProfileOverride>,
    apparmor: OverrideState<SecurityProfileOverride>,
    no_new_privileges: OverrideState<bool>,
    system_paths: OverrideState<bool>,
    seccomp_unconfined_seen: bool,
    apparmor_unconfined_seen: bool,
    no_new_privileges_disabled_seen: bool,
    system_paths_unconfined_seen: bool,
    incomplete_reasons: Vec<DockerSecurityIncompleteReason>,
}

fn valid_network_mode(value: &str) -> bool {
    let generally_valid = !value.is_empty()
        && value.len() <= 256
        && value == value.trim()
        && !value.chars().any(char::is_control);
    generally_valid
        && value
            .strip_prefix("container:")
            .map(valid_container_mode_target)
            .unwrap_or(true)
}

fn valid_pid_mode(value: &str) -> bool {
    value.is_empty()
        || value == "host"
        || value
            .strip_prefix("container:")
            .map(valid_container_mode_target)
            .unwrap_or(false)
}

fn valid_ipc_mode(value: &str) -> bool {
    matches!(value, "none" | "private" | "shareable" | "host")
        || value
            .strip_prefix("container:")
            .map(valid_container_mode_target)
            .unwrap_or(false)
}

fn valid_container_mode_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn valid_absolute_mount_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && (value == "/"
            || (!value.ends_with('/')
                && value
                    .split('/')
                    .skip(1)
                    .all(|component| !component.is_empty() && !matches!(component, "." | ".."))))
}

fn valid_bounded_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn valid_container_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn is_valid_container_target(value: &str) -> bool {
    valid_container_identity(value)
}

fn valid_container_id(value: &str) -> bool {
    (12..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_selinux_process_label(value: Option<&str>) -> SecurityFact {
    let Some(value) = value else {
        return SecurityFact::Unknown(DockerSecurityIncompleteReason::MissingSelinuxProcessLabel);
    };
    if value.is_empty() {
        return SecurityFact::Disabled;
    }
    if !valid_bounded_value(value, 512) {
        return SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidSelinuxProcessLabel);
    }
    let mut fields = value.split(':');
    let user = fields.next().unwrap_or_default();
    let role = fields.next().unwrap_or_default();
    let label_type = fields.next().unwrap_or_default();
    let level = fields.next().unwrap_or_default();
    if user.is_empty() || role.is_empty() || label_type.is_empty() || level.is_empty() {
        return SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidSelinuxProcessLabel);
    }
    match label_type {
        "container_t" | "svirt_lxc_net_t" => SecurityFact::Enabled,
        "spc_t" | "unconfined_t" => SecurityFact::Disabled,
        _ => SecurityFact::Unknown(DockerSecurityIncompleteReason::UnclassifiedSelinuxProcessLabel),
    }
}

fn parse_selinux_enforcement(bytes: &[u8]) -> SecurityFact {
    match bytes {
        b"1" | b"1\n" => SecurityFact::Enabled,
        b"0" | b"0\n" => SecurityFact::Disabled,
        _ => SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidSelinuxEnforcement),
    }
}

async fn read_selinux_enforcement() -> SecurityFact {
    let file = match tokio::fs::File::open("/sys/fs/selinux/enforce").await {
        Ok(file) => file,
        Err(_) => {
            return SecurityFact::Unknown(
                DockerSecurityIncompleteReason::SelinuxEnforcementUnavailable,
            );
        }
    };
    let mut bytes = Vec::with_capacity(16);
    let mut bounded = file.take(16);
    if bounded.read_to_end(&mut bytes).await.is_err() {
        return SecurityFact::Unknown(
            DockerSecurityIncompleteReason::SelinuxEnforcementUnavailable,
        );
    }
    parse_selinux_enforcement(&bytes)
}

fn closed_docker_error(_error: &bollard::errors::Error, code: &'static str) -> String {
    code.to_string()
}

fn push_unique_reason(
    reasons: &mut Vec<DockerSecurityIncompleteReason>,
    reason: DockerSecurityIncompleteReason,
) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn split_security_option(value: &str) -> Option<(&str, &str)> {
    let separator = match (value.find('='), value.find(':')) {
        (Some(left), Some(right)) => left.min(right),
        (Some(index), None) | (None, Some(index)) => index,
        (None, None) => return None,
    };
    Some((&value[..separator], &value[separator + 1..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityOptionKey {
    Seccomp,
    AppArmor,
    NoNewPrivileges,
    SystemPaths,
}

fn security_option_key(value: &str) -> Option<SecurityOptionKey> {
    if value.eq_ignore_ascii_case("seccomp") {
        Some(SecurityOptionKey::Seccomp)
    } else if value.eq_ignore_ascii_case("apparmor") {
        Some(SecurityOptionKey::AppArmor)
    } else if value.eq_ignore_ascii_case("no-new-privileges") {
        Some(SecurityOptionKey::NoNewPrivileges)
    } else if value.eq_ignore_ascii_case("systempaths") {
        Some(SecurityOptionKey::SystemPaths)
    } else {
        None
    }
}

fn suspicious_security_option_key(value: &str) -> Option<SecurityOptionKey> {
    let value = value.trim();
    for (name, key) in [
        ("seccomp", SecurityOptionKey::Seccomp),
        ("apparmor", SecurityOptionKey::AppArmor),
        ("no-new-privileges", SecurityOptionKey::NoNewPrivileges),
        ("systempaths", SecurityOptionKey::SystemPaths),
    ] {
        let Some(prefix) = value.get(..name.len()) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case(name) {
            continue;
        }
        let Some(remainder) = value.get(name.len()..) else {
            continue;
        };
        if remainder.is_empty()
            || remainder
                .chars()
                .next()
                .is_some_and(|next| !next.is_ascii_alphanumeric() && !matches!(next, '-' | '_'))
        {
            return Some(key);
        }
    }
    None
}

fn set_security_override<T: PartialEq>(
    state: &mut OverrideState<T>,
    value: Result<T, ()>,
    reasons: &mut Vec<DockerSecurityIncompleteReason>,
) {
    match value {
        Err(()) => {
            if !matches!(state, OverrideState::Absent) {
                push_unique_reason(
                    reasons,
                    DockerSecurityIncompleteReason::DuplicateSecurityOption,
                );
            }
            *state = OverrideState::Invalid;
            push_unique_reason(
                reasons,
                DockerSecurityIncompleteReason::MalformedSecurityOption,
            );
        }
        Ok(value) => match state {
            OverrideState::Absent => *state = OverrideState::Value(value),
            OverrideState::Value(previous) if *previous == value => {
                *state = OverrideState::Invalid;
                push_unique_reason(
                    reasons,
                    DockerSecurityIncompleteReason::DuplicateSecurityOption,
                );
            }
            OverrideState::Value(_) => {
                *state = OverrideState::Invalid;
                push_unique_reason(
                    reasons,
                    DockerSecurityIncompleteReason::ConflictingSecurityOption,
                );
            }
            OverrideState::Invalid => {
                push_unique_reason(
                    reasons,
                    DockerSecurityIncompleteReason::DuplicateSecurityOption,
                );
            }
        },
    }
}

fn parse_profile_override(
    value: &str,
    max_len: usize,
    known_profile: &str,
) -> Result<SecurityProfileOverride, ()> {
    if !valid_bounded_value(value, max_len) || value.contains(['=', ':']) {
        return Err(());
    }
    if value.eq_ignore_ascii_case("unconfined") {
        Ok(SecurityProfileOverride::Unconfined)
    } else if value.eq_ignore_ascii_case(known_profile) {
        Ok(SecurityProfileOverride::KnownConfined(
            known_profile.to_string(),
        ))
    } else {
        Ok(SecurityProfileOverride::Unclassified(value.to_string()))
    }
}

fn parse_security_options(options: Option<&[String]>) -> ParsedSecurityOptions {
    let mut parsed = ParsedSecurityOptions::default();
    let Some(options) = options else {
        return parsed;
    };
    let option_limit_exceeded = options.len() > MAX_DOCKER_SECURITY_OPTIONS;
    if option_limit_exceeded {
        push_unique_reason(
            &mut parsed.incomplete_reasons,
            DockerSecurityIncompleteReason::SecurityOptionLimitExceeded,
        );
    }

    for option in options.iter().take(MAX_DOCKER_SECURITY_OPTIONS) {
        if option.eq_ignore_ascii_case("no-new-privileges") {
            set_security_override(
                &mut parsed.no_new_privileges,
                Ok(true),
                &mut parsed.incomplete_reasons,
            );
            continue;
        }
        let split = split_security_option(option);
        let key = split
            .and_then(|(key, _)| security_option_key(key))
            .or_else(|| suspicious_security_option_key(option));
        let Some(key) = key else {
            continue;
        };
        let value = split.and_then(|(raw_key, value)| {
            (security_option_key(raw_key) == Some(key)
                && option == option.trim()
                && option.len() <= 4096
                && !option.chars().any(char::is_control))
            .then_some(value)
        });

        match key {
            SecurityOptionKey::Seccomp => {
                let parsed_value = value
                    .ok_or(())
                    .and_then(|value| parse_profile_override(value, 4096, "builtin"));
                if matches!(&parsed_value, Ok(SecurityProfileOverride::Unconfined)) {
                    parsed.seccomp_unconfined_seen = true;
                }
                if matches!(&parsed_value, Ok(SecurityProfileOverride::Unclassified(_))) {
                    push_unique_reason(
                        &mut parsed.incomplete_reasons,
                        DockerSecurityIncompleteReason::UnclassifiedSecurityProfile,
                    );
                }
                set_security_override(
                    &mut parsed.seccomp,
                    parsed_value,
                    &mut parsed.incomplete_reasons,
                );
            }
            SecurityOptionKey::AppArmor => {
                let parsed_value = value
                    .ok_or(())
                    .and_then(|value| parse_profile_override(value, 256, "docker-default"));
                if matches!(&parsed_value, Ok(SecurityProfileOverride::Unconfined)) {
                    parsed.apparmor_unconfined_seen = true;
                }
                if matches!(&parsed_value, Ok(SecurityProfileOverride::Unclassified(_))) {
                    push_unique_reason(
                        &mut parsed.incomplete_reasons,
                        DockerSecurityIncompleteReason::UnclassifiedSecurityProfile,
                    );
                }
                set_security_override(
                    &mut parsed.apparmor,
                    parsed_value,
                    &mut parsed.incomplete_reasons,
                );
            }
            SecurityOptionKey::NoNewPrivileges => {
                let parsed_value = value.ok_or(()).and_then(|value| {
                    if value.eq_ignore_ascii_case("true") {
                        Ok(true)
                    } else if value.eq_ignore_ascii_case("false") {
                        Ok(false)
                    } else {
                        Err(())
                    }
                });
                if parsed_value == Ok(false) {
                    parsed.no_new_privileges_disabled_seen = true;
                }
                set_security_override(
                    &mut parsed.no_new_privileges,
                    parsed_value,
                    &mut parsed.incomplete_reasons,
                );
            }
            SecurityOptionKey::SystemPaths => {
                let parsed_value = value.ok_or(()).and_then(|value| {
                    value
                        .eq_ignore_ascii_case("unconfined")
                        .then_some(true)
                        .ok_or(())
                });
                if parsed_value == Ok(true) {
                    parsed.system_paths_unconfined_seen = true;
                }
                set_security_override(
                    &mut parsed.system_paths,
                    parsed_value,
                    &mut parsed.incomplete_reasons,
                );
            }
        }
    }

    if option_limit_exceeded {
        parsed.seccomp = OverrideState::Invalid;
        parsed.apparmor = OverrideState::Invalid;
        parsed.no_new_privileges = OverrideState::Invalid;
        parsed.system_paths = OverrideState::Invalid;
    }

    parsed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonSecurityFeature {
    Seccomp,
    NoNewPrivileges,
    Userns,
    Selinux,
}

fn daemon_feature_from_head(value: &str) -> Option<(DaemonSecurityFeature, bool)> {
    if value.eq_ignore_ascii_case("seccomp") {
        return Some((DaemonSecurityFeature::Seccomp, true));
    }
    if value.eq_ignore_ascii_case("no-new-privileges") {
        return Some((DaemonSecurityFeature::NoNewPrivileges, true));
    }
    if value.eq_ignore_ascii_case("userns") {
        return Some((DaemonSecurityFeature::Userns, true));
    }
    if value.eq_ignore_ascii_case("selinux") {
        return Some((DaemonSecurityFeature::Selinux, true));
    }

    let Some((key, feature)) = split_security_option(value) else {
        return suspicious_security_option_key(value).and_then(|key| match key {
            SecurityOptionKey::Seccomp => Some((DaemonSecurityFeature::Seccomp, false)),
            SecurityOptionKey::NoNewPrivileges => {
                Some((DaemonSecurityFeature::NoNewPrivileges, false))
            }
            SecurityOptionKey::AppArmor | SecurityOptionKey::SystemPaths => None,
        });
    };
    if key.eq_ignore_ascii_case("name") {
        if feature.eq_ignore_ascii_case("seccomp") {
            Some((DaemonSecurityFeature::Seccomp, true))
        } else if feature.eq_ignore_ascii_case("no-new-privileges") {
            Some((DaemonSecurityFeature::NoNewPrivileges, true))
        } else if feature.eq_ignore_ascii_case("userns") {
            Some((DaemonSecurityFeature::Userns, true))
        } else if feature.eq_ignore_ascii_case("selinux") {
            Some((DaemonSecurityFeature::Selinux, true))
        } else {
            None
        }
    } else if key.eq_ignore_ascii_case("seccomp") {
        Some((DaemonSecurityFeature::Seccomp, false))
    } else if key.eq_ignore_ascii_case("no-new-privileges") {
        Some((DaemonSecurityFeature::NoNewPrivileges, false))
    } else {
        None
    }
}

fn suspicious_daemon_feature(value: &str) -> Option<DaemonSecurityFeature> {
    let lower = value.trim().to_ascii_lowercase();
    for (prefix, feature) in [
        ("seccomp", DaemonSecurityFeature::Seccomp),
        ("name=seccomp", DaemonSecurityFeature::Seccomp),
        ("name:seccomp", DaemonSecurityFeature::Seccomp),
        ("no-new-privileges", DaemonSecurityFeature::NoNewPrivileges),
        (
            "name=no-new-privileges",
            DaemonSecurityFeature::NoNewPrivileges,
        ),
        (
            "name:no-new-privileges",
            DaemonSecurityFeature::NoNewPrivileges,
        ),
        ("userns", DaemonSecurityFeature::Userns),
        ("name=userns", DaemonSecurityFeature::Userns),
        ("name:userns", DaemonSecurityFeature::Userns),
        ("selinux", DaemonSecurityFeature::Selinux),
        ("name=selinux", DaemonSecurityFeature::Selinux),
        ("name:selinux", DaemonSecurityFeature::Selinux),
    ] {
        let Some(remainder) = lower.strip_prefix(prefix) else {
            continue;
        };
        if remainder.is_empty()
            || remainder
                .chars()
                .next()
                .is_some_and(|next| !next.is_ascii_alphanumeric() && !matches!(next, '-' | '_'))
        {
            return Some(feature);
        }
    }
    None
}

fn set_daemon_fact(current: &mut Option<SecurityFact>, fact: SecurityFact) {
    *current = Some(match current {
        None => fact,
        Some(previous) if *previous == fact => {
            SecurityFact::Unknown(DockerSecurityIncompleteReason::DuplicateDaemonSecurityOption)
        }
        Some(_) => {
            SecurityFact::Unknown(DockerSecurityIncompleteReason::ConflictingDaemonSecurityOption)
        }
    });
}

fn parse_daemon_security_options(options: Option<&[String]>) -> DockerDaemonSecurityFacts {
    let Some(options) = options else {
        return DockerDaemonSecurityFacts::unknown(
            DockerSecurityIncompleteReason::MissingDaemonSecurityOptions,
        );
    };
    let option_limit_exceeded = options.len() > MAX_DOCKER_DAEMON_SECURITY_OPTIONS;
    let mut seccomp = None;
    let mut no_new_privileges = None;
    let mut userns = None;
    let mut selinux = None;
    let mut seccomp_unconfined_seen = false;

    for option in options.iter().take(MAX_DOCKER_DAEMON_SECURITY_OPTIONS) {
        let mut fields = option.split(',');
        let head = fields.next().unwrap_or_default();
        let Some((feature, valid_head)) = daemon_feature_from_head(head.trim()) else {
            if let Some(feature) = suspicious_daemon_feature(head) {
                let fact = SecurityFact::Unknown(
                    DockerSecurityIncompleteReason::InvalidDaemonSecurityOption,
                );
                match feature {
                    DaemonSecurityFeature::Seccomp => set_daemon_fact(&mut seccomp, fact),
                    DaemonSecurityFeature::NoNewPrivileges => {
                        set_daemon_fact(&mut no_new_privileges, fact)
                    }
                    DaemonSecurityFeature::Userns => set_daemon_fact(&mut userns, fact),
                    DaemonSecurityFeature::Selinux => set_daemon_fact(&mut selinux, fact),
                }
            }
            continue;
        };
        let mut valid = valid_head
            && valid_bounded_value(option, 512)
            && head == head.trim()
            && !head.is_empty();
        let mut seccomp_enabled = true;
        let mut seccomp_unclassified = false;
        let mut profile_seen = false;

        for field in fields {
            let Some((key, value)) = split_security_option(field) else {
                valid = false;
                continue;
            };
            if !valid_bounded_value(key, 64) || !valid_bounded_value(value, 256) {
                valid = false;
                continue;
            }
            if feature != DaemonSecurityFeature::Seccomp || !key.eq_ignore_ascii_case("profile") {
                valid = false;
                continue;
            }
            if profile_seen {
                valid = false;
            }
            profile_seen = true;
            if value.eq_ignore_ascii_case("unconfined") {
                seccomp_enabled = false;
            } else if !value.eq_ignore_ascii_case("builtin") {
                seccomp_unclassified = true;
            }
        }

        let fact = if !valid {
            SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidDaemonSecurityOption)
        } else if feature == DaemonSecurityFeature::Seccomp && seccomp_unclassified {
            SecurityFact::Unknown(DockerSecurityIncompleteReason::UnclassifiedSecurityProfile)
        } else {
            match feature {
                DaemonSecurityFeature::Seccomp if seccomp_enabled => SecurityFact::Enabled,
                DaemonSecurityFeature::Seccomp => SecurityFact::Disabled,
                DaemonSecurityFeature::NoNewPrivileges => SecurityFact::Enabled,
                DaemonSecurityFeature::Userns => SecurityFact::Enabled,
                DaemonSecurityFeature::Selinux => SecurityFact::Enabled,
            }
        };
        if feature == DaemonSecurityFeature::Seccomp && valid && !seccomp_enabled {
            seccomp_unconfined_seen = true;
        }
        match feature {
            DaemonSecurityFeature::Seccomp => set_daemon_fact(&mut seccomp, fact),
            DaemonSecurityFeature::NoNewPrivileges => set_daemon_fact(&mut no_new_privileges, fact),
            DaemonSecurityFeature::Userns => set_daemon_fact(&mut userns, fact),
            DaemonSecurityFeature::Selinux => set_daemon_fact(&mut selinux, fact),
        }
    }

    let missing_fact = || {
        if option_limit_exceeded {
            SecurityFact::Unknown(DockerSecurityIncompleteReason::DaemonSecurityOptionLimitExceeded)
        } else {
            SecurityFact::Disabled
        }
    };
    DockerDaemonSecurityFacts {
        seccomp: seccomp.unwrap_or_else(missing_fact),
        no_new_privileges: no_new_privileges.unwrap_or_else(missing_fact),
        userns: userns.unwrap_or_else(missing_fact),
        selinux: selinux.unwrap_or_else(missing_fact),
        seccomp_unconfined_seen,
        option_limit_exceeded,
    }
}

pub struct DockerService {
    docker: Docker,
}

impl DockerService {
    pub fn new() -> Result<Self, String> {
        let docker = Docker::connect_with_socket_defaults()
            .map_err(|error| closed_docker_error(&error, "docker_connection_failed"))?;
        Ok(Self { docker })
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>, String> {
        let options = ListContainersOptions {
            all: true,
            ..Default::default()
        };

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(|error| closed_docker_error(&error, "docker_list_failed"))?;

        let result = containers
            .into_iter()
            .map(|c| {
                let name = c
                    .names
                    .clone()
                    .unwrap_or_default()
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
                    .trim_start_matches('/')
                    .to_string();

                let ports = c
                    .ports
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|p| format!("{}:{}", p.public_port.unwrap_or(0), p.private_port))
                    .collect::<Vec<_>>()
                    .join(", ");

                ContainerInfo {
                    id: c.id.unwrap_or_default(),
                    name,
                    image: c.image.unwrap_or_default(),
                    status: c.status.unwrap_or_default(),
                    state: c
                        .state
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    ports,
                }
            })
            .collect();

        Ok(result)
    }

    async fn list_audit_container_identities(
        &self,
    ) -> Result<(Vec<AuditContainerIdentity>, bool, bool), ()> {
        let options = ListContainersOptions {
            all: true,
            limit: Some((MAX_DOCKER_AUDIT_CONTAINERS + 1) as i32),
            ..Default::default()
        };
        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(|_| ())?;
        let limit_exceeded = containers.len() > MAX_DOCKER_AUDIT_CONTAINERS;
        let mut invalid_identity = false;
        let mut identities = Vec::with_capacity(containers.len().min(MAX_DOCKER_AUDIT_CONTAINERS));

        for container in containers.into_iter().take(MAX_DOCKER_AUDIT_CONTAINERS) {
            let Some(id) = container.id.filter(|value| valid_container_id(value)) else {
                invalid_identity = true;
                continue;
            };
            let fallback_name = container
                .names
                .as_deref()
                .and_then(|names| names.first())
                .map(|name| name.trim_start_matches('/'))
                .filter(|name| valid_container_identity(name))
                .unwrap_or_else(|| {
                    invalid_identity = true;
                    "unknown"
                })
                .to_string();
            identities.push(AuditContainerIdentity { id, fallback_name });
        }

        Ok((identities, invalid_identity, limit_exceeded))
    }

    pub async fn audit_security_risks(&self, timeout: Duration) -> DockerSecurityAuditOutcome {
        let mut outcome = DockerSecurityAuditOutcome::default();
        let deadline = tokio::time::Instant::now() + timeout;
        let (containers, invalid_identity, limit_exceeded) =
            match tokio::time::timeout_at(deadline, self.list_audit_container_identities()).await {
                Ok(Ok(result)) => result,
                Ok(Err(())) => {
                    outcome
                        .mark_incomplete(DockerSecurityIncompleteReason::ListContainersUnavailable);
                    return outcome;
                }
                Err(_) => {
                    outcome.mark_incomplete(
                        DockerSecurityIncompleteReason::DockerAuditDeadlineExceeded,
                    );
                    return outcome;
                }
            };
        if invalid_identity {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidContainerIdentity);
        }
        if limit_exceeded {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::ContainerLimitExceeded);
        }
        if containers.is_empty() {
            return outcome;
        }

        let mut daemon_facts = match tokio::time::timeout_at(deadline, self.docker.info()).await {
            Ok(Ok(info)) => parse_daemon_security_options(info.security_options.as_deref()),
            Ok(Err(_)) => DockerDaemonSecurityFacts::unknown(
                DockerSecurityIncompleteReason::DockerInfoUnavailable,
            ),
            Err(_) => {
                outcome
                    .mark_incomplete(DockerSecurityIncompleteReason::DockerAuditDeadlineExceeded);
                return outcome;
            }
        };
        if daemon_facts.selinux == SecurityFact::Enabled {
            daemon_facts.selinux =
                match tokio::time::timeout_at(deadline, read_selinux_enforcement()).await {
                    Ok(fact) => fact,
                    Err(_) => {
                        outcome.mark_incomplete(
                            DockerSecurityIncompleteReason::DockerAuditDeadlineExceeded,
                        );
                        return outcome;
                    }
                };
        }

        for container in containers {
            match tokio::time::timeout_at(
                deadline,
                self.docker
                    .inspect_container(&container.id, None::<InspectContainerOptions>),
            )
            .await
            {
                Ok(Ok(inspect)) => outcome.merge(Self::evaluate_inspect_security_risks(
                    &inspect,
                    &container.fallback_name,
                    daemon_facts,
                )),
                Ok(Err(_)) => outcome
                    .mark_incomplete(DockerSecurityIncompleteReason::InspectContainerUnavailable),
                Err(_) => {
                    outcome.mark_incomplete(
                        DockerSecurityIncompleteReason::DockerAuditDeadlineExceeded,
                    );
                    break;
                }
            }
        }

        outcome
    }

    fn evaluate_inspect_security_risks(
        inspect: &ContainerInspectResponse,
        fallback_name: &str,
        daemon_facts: DockerDaemonSecurityFacts,
    ) -> DockerSecurityAuditOutcome {
        let mut outcome = DockerSecurityAuditOutcome::default();
        if daemon_facts.option_limit_exceeded {
            outcome
                .mark_incomplete(DockerSecurityIncompleteReason::DaemonSecurityOptionLimitExceeded);
        }
        let candidate_name = inspect
            .name
            .as_deref()
            .unwrap_or(fallback_name)
            .trim_start_matches('/');
        let container_name = if valid_container_identity(candidate_name) {
            candidate_name
        } else {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidContainerIdentity);
            "unknown"
        };

        if let Some(host_config) = inspect.host_config.as_ref() {
            match host_config.privileged {
                Some(true) => outcome.risks.push(DockerSecurityRisk {
                    severity: "critical".to_string(),
                    finding: "Privileged container".to_string(),
                    evidence: format!("container={} privileged=true", container_name),
                }),
                Some(false) => {}
                None => outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingPrivileged),
            }

            match host_config.network_mode.as_deref() {
                Some(value) if valid_network_mode(value) => Self::push_host_namespace_risk(
                    &mut outcome.risks,
                    container_name,
                    "network_mode",
                    Some(value),
                    "host network namespace",
                    "high",
                ),
                Some(_) => {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidNetworkMode)
                }
                None => outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingNetworkMode),
            }
            match host_config.pid_mode.as_deref() {
                Some(value) if valid_pid_mode(value) => Self::push_host_namespace_risk(
                    &mut outcome.risks,
                    container_name,
                    "pid_mode",
                    Some(value),
                    "host PID namespace",
                    "high",
                ),
                Some(_) => outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidPidMode),
                None => outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingPidMode),
            }
            match host_config.ipc_mode.as_deref() {
                Some(value) if valid_ipc_mode(value) => Self::push_host_namespace_risk(
                    &mut outcome.risks,
                    container_name,
                    "ipc_mode",
                    Some(value),
                    "host IPC namespace",
                    "medium",
                ),
                Some(_) => outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidIpcMode),
                None => outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingIpcMode),
            }
            match host_config.userns_mode.as_deref() {
                Some("") => {
                    Self::evaluate_userns(&mut outcome, container_name, daemon_facts.userns)
                }
                Some("host") => outcome.risks.push(DockerSecurityRisk {
                    severity: "medium".to_string(),
                    finding: "Host user namespace".to_string(),
                    evidence: format!("container={} userns_mode=host", container_name),
                }),
                Some(_) => {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidUsernsMode)
                }
                None => outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingUsernsMode),
            }
            match host_config.uts_mode.as_deref() {
                Some("") => {}
                Some("host") => outcome.risks.push(DockerSecurityRisk {
                    severity: "high".to_string(),
                    finding: "Host UTS namespace".to_string(),
                    evidence: format!("container={} uts_mode=host", container_name),
                }),
                Some(_) => outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidUtsMode),
                None => outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingUtsMode),
            }
            match host_config.cgroupns_mode {
                Some(HostConfigCgroupnsModeEnum::HOST) => {
                    outcome.risks.push(DockerSecurityRisk {
                        severity: "medium".to_string(),
                        finding: "Host cgroup namespace".to_string(),
                        evidence: format!("container={} cgroupns_mode=host", container_name),
                    });
                }
                Some(HostConfigCgroupnsModeEnum::EMPTY) => {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::AmbiguousCgroupnsMode)
                }
                Some(_) => {}
                None => {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingCgroupnsMode)
                }
            }

            if let Some(caps) = host_config.cap_add.as_ref() {
                if caps.len() > MAX_DOCKER_AUDIT_CAPABILITIES {
                    outcome
                        .mark_incomplete(DockerSecurityIncompleteReason::CapabilityLimitExceeded);
                }
                for cap in caps.iter().take(MAX_DOCKER_AUDIT_CAPABILITIES) {
                    match Self::dangerous_capability(cap) {
                        Ok((severity, normalized)) => outcome.risks.push(DockerSecurityRisk {
                            severity: severity.to_string(),
                            finding: "Explicit Linux capability".to_string(),
                            evidence: format!(
                                "container={} cap_add={}",
                                container_name, normalized
                            ),
                        }),
                        Err(()) => outcome
                            .mark_incomplete(DockerSecurityIncompleteReason::InvalidCapability),
                    }
                }
            }

            for (count, finding, severity, evidence_key) in [
                (
                    host_config.devices.as_ref().map(Vec::len).unwrap_or(0),
                    "Host device mapping",
                    "high",
                    "device_mapping_count",
                ),
                (
                    host_config
                        .device_cgroup_rules
                        .as_ref()
                        .map(Vec::len)
                        .unwrap_or(0),
                    "Device cgroup rule",
                    "high",
                    "device_rule_count",
                ),
                (
                    host_config
                        .device_requests
                        .as_ref()
                        .map(Vec::len)
                        .unwrap_or(0),
                    "Device driver request",
                    "medium",
                    "device_request_count",
                ),
            ] {
                if count > MAX_DOCKER_AUDIT_DEVICE_ITEMS {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::DeviceLimitExceeded);
                }
                if count > 0 {
                    outcome.risks.push(DockerSecurityRisk {
                        severity: severity.to_string(),
                        finding: finding.to_string(),
                        evidence: format!(
                            "container={} {}={}",
                            container_name,
                            evidence_key,
                            count.min(MAX_DOCKER_AUDIT_DEVICE_ITEMS)
                        ),
                    });
                }
            }

            let security_options = parse_security_options(host_config.security_opt.as_deref());
            for reason in &security_options.incomplete_reasons {
                outcome.mark_incomplete(*reason);
            }
            Self::evaluate_system_paths(
                &mut outcome,
                container_name,
                host_config.masked_paths.as_deref(),
                host_config.readonly_paths.as_deref(),
                security_options.system_paths_unconfined_seen,
            );
            Self::evaluate_seccomp(
                &mut outcome,
                container_name,
                &security_options.seccomp,
                security_options.seccomp_unconfined_seen,
                daemon_facts.seccomp,
                daemon_facts.seccomp_unconfined_seen,
            );
            Self::evaluate_no_new_privileges(
                &mut outcome,
                container_name,
                &security_options.no_new_privileges,
                security_options.no_new_privileges_disabled_seen,
                daemon_facts.no_new_privileges,
            );
            Self::evaluate_mac_confinement(
                &mut outcome,
                container_name,
                inspect.app_armor_profile.as_deref(),
                inspect.process_label.as_deref(),
                &security_options.apparmor,
                security_options.apparmor_unconfined_seen,
                daemon_facts.selinux,
            );
        } else {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingHostConfig);
            Self::evaluate_mac_confinement(
                &mut outcome,
                container_name,
                inspect.app_armor_profile.as_deref(),
                inspect.process_label.as_deref(),
                &OverrideState::Absent,
                false,
                daemon_facts.selinux,
            );
        }

        if let Some(mounts) = inspect.mounts.as_ref() {
            if mounts.len() > MAX_DOCKER_AUDIT_MOUNTS {
                outcome.mark_incomplete(DockerSecurityIncompleteReason::MountLimitExceeded);
            }
            for mount in mounts.iter().take(MAX_DOCKER_AUDIT_MOUNTS) {
                let Some(mount_type) = mount.typ else {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::IncompleteMountType);
                    continue;
                };
                if mount_type == MountPointTypeEnum::EMPTY {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::IncompleteMountType);
                    continue;
                }
                if mount_type != MountPointTypeEnum::BIND {
                    continue;
                }

                let source = mount
                    .source
                    .as_deref()
                    .filter(|value| valid_absolute_mount_path(value));
                if source.is_none() {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::IncompleteBindSource);
                }
                let destination = mount
                    .destination
                    .as_deref()
                    .filter(|value| valid_absolute_mount_path(value));
                if destination.is_none() {
                    outcome
                        .mark_incomplete(DockerSecurityIncompleteReason::IncompleteBindDestination);
                }
                let writable = mount.rw;
                if writable.is_none() {
                    outcome.mark_incomplete(DockerSecurityIncompleteReason::IncompleteBindWritable);
                }

                if let (Some(source), Some(writable)) = (source, writable)
                    && let Some((severity, label)) = Self::sensitive_mount(source, writable)
                {
                    outcome.risks.push(DockerSecurityRisk {
                        severity: severity.to_string(),
                        finding: "Sensitive host bind mount".to_string(),
                        evidence: format!(
                            "container={} rw={} surface={}",
                            container_name, writable, label
                        ),
                    });
                }
            }
        } else {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingMounts);
        }

        outcome.enforce_risk_limit();
        outcome
    }

    fn evaluate_system_paths(
        outcome: &mut DockerSecurityAuditOutcome,
        container_name: &str,
        masked_paths: Option<&[String]>,
        readonly_paths: Option<&[String]>,
        explicit_unconfined: bool,
    ) {
        const REQUIRED_MASKED: &[&str] = &["/proc/kcore", "/proc/keys"];
        const REQUIRED_READONLY: &[&str] = &["/proc/sys", "/proc/sysrq-trigger"];

        if explicit_unconfined {
            outcome.risks.push(DockerSecurityRisk {
                severity: "high".to_string(),
                finding: "Container system paths unconfined".to_string(),
                evidence: format!("container={} systempaths=unconfined", container_name),
            });
        }

        let Some(masked_paths) = masked_paths else {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingMaskedPaths);
            return;
        };
        let Some(readonly_paths) = readonly_paths else {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::MissingReadonlyPaths);
            return;
        };
        if masked_paths.len() > MAX_DOCKER_SYSTEM_PATHS
            || readonly_paths.len() > MAX_DOCKER_SYSTEM_PATHS
            || masked_paths
                .iter()
                .chain(readonly_paths)
                .any(|path| !valid_absolute_mount_path(path))
        {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidSystemPaths);
            return;
        }

        let required_missing = REQUIRED_MASKED
            .iter()
            .any(|required| !masked_paths.iter().any(|path| path == required))
            || REQUIRED_READONLY
                .iter()
                .any(|required| !readonly_paths.iter().any(|path| path == required));
        if required_missing && !explicit_unconfined {
            outcome.risks.push(DockerSecurityRisk {
                severity: "high".to_string(),
                finding: "Container system paths unconfined".to_string(),
                evidence: format!("container={} systempaths=unconfined", container_name),
            });
        }
    }

    fn evaluate_seccomp(
        outcome: &mut DockerSecurityAuditOutcome,
        container_name: &str,
        container_override: &OverrideState<SecurityProfileOverride>,
        container_unconfined_seen: bool,
        daemon_fact: SecurityFact,
        daemon_unconfined_seen: bool,
    ) {
        let (fact, unsafe_seen) = match container_override {
            OverrideState::Value(SecurityProfileOverride::KnownConfined(_)) => {
                (Some(SecurityFact::Enabled), container_unconfined_seen)
            }
            OverrideState::Value(SecurityProfileOverride::Unconfined) => {
                (Some(SecurityFact::Disabled), true)
            }
            OverrideState::Absent => (
                Some(daemon_fact),
                container_unconfined_seen || daemon_unconfined_seen,
            ),
            OverrideState::Invalid => (None, container_unconfined_seen || daemon_unconfined_seen),
            OverrideState::Value(SecurityProfileOverride::Unclassified(_)) => {
                (None, container_unconfined_seen || daemon_unconfined_seen)
            }
        };
        if unsafe_seen || fact == Some(SecurityFact::Disabled) {
            outcome.risks.push(DockerSecurityRisk {
                severity: "high".to_string(),
                finding: "Seccomp disabled".to_string(),
                evidence: format!("container={} seccomp=disabled", container_name),
            });
        }
        if let Some(SecurityFact::Unknown(reason)) = fact {
            outcome.mark_incomplete(reason);
        }
    }

    fn evaluate_userns(
        outcome: &mut DockerSecurityAuditOutcome,
        container_name: &str,
        daemon_fact: SecurityFact,
    ) {
        match daemon_fact {
            SecurityFact::Enabled => {}
            SecurityFact::Disabled => outcome.risks.push(DockerSecurityRisk {
                severity: "medium".to_string(),
                finding: "Host user namespace".to_string(),
                evidence: format!(
                    "container={} userns_mode=daemon_default_host",
                    container_name
                ),
            }),
            SecurityFact::Unknown(reason) => outcome.mark_incomplete(reason),
        }
    }

    fn evaluate_no_new_privileges(
        outcome: &mut DockerSecurityAuditOutcome,
        container_name: &str,
        container_override: &OverrideState<bool>,
        container_disabled_seen: bool,
        daemon_fact: SecurityFact,
    ) {
        let fact = match container_override {
            OverrideState::Value(true) => Some(SecurityFact::Enabled),
            OverrideState::Value(false) => Some(SecurityFact::Disabled),
            OverrideState::Absent => Some(daemon_fact),
            OverrideState::Invalid => None,
        };
        if container_disabled_seen || fact == Some(SecurityFact::Disabled) {
            outcome.risks.push(DockerSecurityRisk {
                severity: "medium".to_string(),
                finding: "no-new-privileges disabled".to_string(),
                evidence: format!("container={} no_new_privileges=false", container_name),
            });
        }
        if let Some(SecurityFact::Unknown(reason)) = fact {
            outcome.mark_incomplete(reason);
        }
    }

    fn evaluate_mac_confinement(
        outcome: &mut DockerSecurityAuditOutcome,
        container_name: &str,
        apparmor_profile: Option<&str>,
        selinux_process_label: Option<&str>,
        container_override: &OverrideState<SecurityProfileOverride>,
        container_unconfined_seen: bool,
        daemon_selinux: SecurityFact,
    ) {
        let apparmor = match apparmor_profile {
            None => None,
            Some("") => Some(SecurityProfileOverride::Unconfined),
            Some(value) if valid_bounded_value(value, 256) => {
                if value.eq_ignore_ascii_case("unconfined") {
                    Some(SecurityProfileOverride::Unconfined)
                } else if value.eq_ignore_ascii_case("docker-default") {
                    Some(SecurityProfileOverride::KnownConfined(
                        "docker-default".to_string(),
                    ))
                } else {
                    outcome.mark_incomplete(
                        DockerSecurityIncompleteReason::UnclassifiedSecurityProfile,
                    );
                    Some(SecurityProfileOverride::Unclassified(value.to_string()))
                }
            }
            Some(_) => {
                outcome.mark_incomplete(DockerSecurityIncompleteReason::InvalidAppArmorProfile);
                None
            }
        };

        if let (Some(inspect), OverrideState::Value(override_profile)) =
            (apparmor.as_ref(), container_override)
            && inspect != override_profile
        {
            outcome.mark_incomplete(DockerSecurityIncompleteReason::ConflictingAppArmorFacts);
        }

        let apparmor_confined = matches!(apparmor, Some(SecurityProfileOverride::KnownConfined(_)));
        let apparmor_unconfined = container_unconfined_seen
            || matches!(apparmor, Some(SecurityProfileOverride::Unconfined))
            || matches!(
                container_override,
                OverrideState::Value(SecurityProfileOverride::Unconfined)
            );

        let selinux = match daemon_selinux {
            SecurityFact::Enabled => parse_selinux_process_label(selinux_process_label),
            other => other,
        };
        if let SecurityFact::Unknown(reason) = selinux {
            outcome.mark_incomplete(reason);
        }

        if apparmor_confined && !container_unconfined_seen {
            return;
        }
        if selinux == SecurityFact::Enabled && !container_unconfined_seen {
            return;
        }
        if apparmor_unconfined && selinux == SecurityFact::Disabled {
            outcome.risks.push(DockerSecurityRisk {
                severity: "high".to_string(),
                finding: "Mandatory access control unconfined".to_string(),
                evidence: format!("container={} mac=unconfined", container_name),
            });
            return;
        }

        let reason = match (apparmor_profile, selinux) {
            (None, _) => DockerSecurityIncompleteReason::MissingAppArmorProfile,
            (_, SecurityFact::Unknown(reason)) => reason,
            _ => DockerSecurityIncompleteReason::MissingAppArmorProfile,
        };
        outcome.mark_incomplete(reason);
        if container_unconfined_seen {
            outcome.risks.push(DockerSecurityRisk {
                severity: "high".to_string(),
                finding: "Mandatory access control unconfined".to_string(),
                evidence: format!("container={} mac=unconfined", container_name),
            });
        }
    }

    fn push_host_namespace_risk(
        risks: &mut Vec<DockerSecurityRisk>,
        container_name: &str,
        key: &str,
        value: Option<&str>,
        finding: &str,
        severity: &str,
    ) {
        if value == Some("host") {
            risks.push(DockerSecurityRisk {
                severity: severity.to_string(),
                finding: finding.to_string(),
                evidence: format!("container={} {}=host", container_name, key),
            });
        }
    }

    fn dangerous_capability(capability: &str) -> Result<(&'static str, String), ()> {
        if !valid_bounded_value(capability, 64) {
            return Err(());
        }
        let uppercase = capability.to_ascii_uppercase();
        let normalized = uppercase.strip_prefix("CAP_").unwrap_or(&uppercase);
        if normalized.is_empty()
            || !normalized
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(());
        }

        let severity = match normalized {
            "ALL" | "SYS_ADMIN" | "SYS_MODULE" | "SYS_BOOT" => "critical",
            "SYS_PTRACE" | "NET_ADMIN" | "SYS_RAWIO" | "DAC_READ_SEARCH" | "DAC_OVERRIDE"
            | "BPF" | "PERFMON" | "SYS_TIME" | "AUDIT_CONTROL" | "MAC_ADMIN" => "high",
            _ => "medium",
        };
        Ok((severity, normalized.to_string()))
    }

    fn sensitive_mount(source: &str, writable: bool) -> Option<(&'static str, &'static str)> {
        const EXACT_HIGH: &[(&str, &str)] = &[
            ("/", "host_root"),
            ("/var/run/docker.sock", "docker_socket"),
            ("/run/docker.sock", "docker_socket"),
            ("/run/containerd/containerd.sock", "containerd_socket"),
        ];
        const PREFIXES: &[(&str, &str)] = &[
            ("/etc", "host_config"),
            ("/root", "root_home"),
            ("/home", "user_homes"),
            ("/proc", "procfs"),
            ("/sys", "sysfs"),
            ("/dev", "host_devices"),
            ("/run", "runtime_state"),
            ("/var/run", "runtime_state"),
            ("/boot", "boot_state"),
            ("/usr", "host_binaries"),
            ("/bin", "host_binaries"),
            ("/sbin", "host_binaries"),
            ("/lib", "host_libraries"),
            ("/lib64", "host_libraries"),
            ("/opt/mini-ops", "agent_installation"),
            ("/var/lib/mini-ops", "agent_state"),
            ("/var/lib/mini-ops-quarantine", "agent_state"),
            ("/var/backups/mini-ops", "agent_state"),
            ("/var/lib/docker", "docker_state"),
            ("/var/lib/containerd", "containerd_state"),
            ("/var/lib/kubelet", "kubelet_state"),
            ("/opt/cni/bin", "cni_plugins"),
        ];

        for (path, label) in EXACT_HIGH {
            if source == *path {
                return Some(("critical", label));
            }
        }

        for (path, label) in PREFIXES {
            if source == *path || source.starts_with(&format!("{}/", path.trim_end_matches('/'))) {
                return Some((if writable { "high" } else { "medium" }, label));
            }
        }

        None
    }

    pub async fn start_container(&self, id: &str) -> Result<(), String> {
        if !is_valid_container_target(id) {
            return Err("invalid_container_target".to_string());
        }
        tracing::info!(docker_action = "start", "Docker container action requested");
        self.docker
            .start_container(id, None::<StartContainerOptions>)
            .await
            .map_err(|error| {
                tracing::error!(
                    docker_error = "action_failed",
                    "Docker container action failed"
                );
                closed_docker_error(&error, "docker_action_failed")
            })
    }

    pub async fn stop_container(&self, id: &str) -> Result<(), String> {
        if !is_valid_container_target(id) {
            return Err("invalid_container_target".to_string());
        }
        tracing::info!(docker_action = "stop", "Docker container action requested");
        self.docker
            .stop_container(id, None::<StopContainerOptions>)
            .await
            .map_err(|error| {
                tracing::error!(
                    docker_error = "action_failed",
                    "Docker container action failed"
                );
                closed_docker_error(&error, "docker_action_failed")
            })
    }

    pub async fn restart_container(&self, id: &str) -> Result<(), String> {
        if !is_valid_container_target(id) {
            return Err("invalid_container_target".to_string());
        }
        tracing::info!(
            docker_action = "restart",
            "Docker container action requested"
        );
        self.docker
            .restart_container(id, None::<RestartContainerOptions>)
            .await
            .map_err(|error| {
                tracing::error!(
                    docker_error = "action_failed",
                    "Docker container action failed"
                );
                closed_docker_error(&error, "docker_action_failed")
            })
    }

    /// Создает поток логов контейнера с поддержкой фильтрации.
    ///
    /// # Аргументы
    /// * `id` - ID контейнера
    /// * `since` - Опциональный timestamp (Unix), начиная с которого нужны логи
    /// * `tail` - Количество строк с конца ("all" или число)
    pub fn logs_stream<'a>(
        &'a self,
        id: &'a str,
        since: Option<i64>,
        tail: Option<String>,
    ) -> futures_util::stream::BoxStream<'a, Result<String, String>> {
        use futures_util::{StreamExt, stream};
        if !is_valid_container_target(id) {
            return stream::once(async { Err("invalid_container_target".to_string()) }).boxed();
        }
        tracing::info!("Docker container log stream requested");

        let options = Some(LogsOptions {
            follow: true,
            stdout: true,
            stderr: true,
            tail: tail.unwrap_or_else(|| "100".to_string()),
            since: since.unwrap_or(0) as i32,
            ..Default::default()
        });

        self.docker
            .logs(id, options)
            .map(|result| {
                result
                    .map(|log| log.to_string())
                    .map_err(|error| closed_docker_error(&error, "docker_log_stream_failed"))
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{DeviceMapping, HostConfig, MountPoint};

    fn valid_empty_risk_inspect() -> ContainerInspectResponse {
        ContainerInspectResponse {
            name: Some("/safe-container".to_string()),
            app_armor_profile: Some("docker-default".to_string()),
            host_config: Some(HostConfig {
                privileged: Some(false),
                network_mode: Some("bridge".to_string()),
                pid_mode: Some(String::new()),
                ipc_mode: Some("private".to_string()),
                userns_mode: Some(String::new()),
                uts_mode: Some(String::new()),
                cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
                masked_paths: Some(vec!["/proc/kcore".to_string(), "/proc/keys".to_string()]),
                readonly_paths: Some(vec![
                    "/proc/sys".to_string(),
                    "/proc/sysrq-trigger".to_string(),
                ]),
                ..Default::default()
            }),
            mounts: Some(Vec::new()),
            ..Default::default()
        }
    }

    fn bind_mount() -> MountPoint {
        MountPoint {
            typ: Some(MountPointTypeEnum::BIND),
            source: Some("/srv/data".to_string()),
            destination: Some("/data".to_string()),
            rw: Some(false),
            ..Default::default()
        }
    }

    fn safe_daemon_security_facts() -> DockerDaemonSecurityFacts {
        DockerDaemonSecurityFacts {
            seccomp: SecurityFact::Enabled,
            no_new_privileges: SecurityFact::Enabled,
            userns: SecurityFact::Enabled,
            selinux: SecurityFact::Disabled,
            seccomp_unconfined_seen: false,
            option_limit_exceeded: false,
        }
    }

    fn evaluate(inspect: &ContainerInspectResponse) -> DockerSecurityAuditOutcome {
        DockerService::evaluate_inspect_security_risks(
            inspect,
            "fallback",
            safe_daemon_security_facts(),
        )
    }

    fn assert_incomplete(
        outcome: &DockerSecurityAuditOutcome,
        expected: DockerSecurityIncompleteReason,
    ) {
        assert!(
            outcome.incomplete_reasons.contains(&expected),
            "expected incomplete reason {expected:?}, got {:?}",
            outcome.incomplete_reasons
        );
    }

    #[test]
    fn absent_host_config_is_unknown_instead_of_empty_risk_pass() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config = None;

        let outcome = evaluate(&inspect);
        assert!(outcome.risks.is_empty());
        assert_incomplete(&outcome, DockerSecurityIncompleteReason::MissingHostConfig);
    }

    #[test]
    fn absent_mounts_is_unknown_instead_of_empty_risk_pass() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.mounts = None;

        let outcome = evaluate(&inspect);
        assert!(outcome.risks.is_empty());
        assert_incomplete(&outcome, DockerSecurityIncompleteReason::MissingMounts);
    }

    #[test]
    fn missing_security_relevant_host_facts_are_unknown() {
        let mut cases = Vec::new();

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().privileged = None;
        cases.push((inspect, DockerSecurityIncompleteReason::MissingPrivileged));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().network_mode = None;
        cases.push((inspect, DockerSecurityIncompleteReason::MissingNetworkMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().pid_mode = None;
        cases.push((inspect, DockerSecurityIncompleteReason::MissingPidMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().ipc_mode = None;
        cases.push((inspect, DockerSecurityIncompleteReason::MissingIpcMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().userns_mode = None;
        cases.push((inspect, DockerSecurityIncompleteReason::MissingUsernsMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().uts_mode = None;
        cases.push((inspect, DockerSecurityIncompleteReason::MissingUtsMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().cgroupns_mode = None;
        cases.push((inspect, DockerSecurityIncompleteReason::MissingCgroupnsMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.app_armor_profile = None;
        cases.push((
            inspect,
            DockerSecurityIncompleteReason::MissingAppArmorProfile,
        ));

        for (inspect, expected) in cases {
            assert_incomplete(&evaluate(&inspect), expected);
        }
    }

    #[test]
    fn ambiguous_or_malformed_namespace_facts_are_unknown() {
        let mut cases = Vec::new();

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().network_mode = Some("container:".to_string());
        cases.push((inspect, DockerSecurityIncompleteReason::InvalidNetworkMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().pid_mode = Some("private".to_string());
        cases.push((inspect, DockerSecurityIncompleteReason::InvalidPidMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().ipc_mode = Some(String::new());
        cases.push((inspect, DockerSecurityIncompleteReason::InvalidIpcMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().userns_mode = Some("private".to_string());
        cases.push((inspect, DockerSecurityIncompleteReason::InvalidUsernsMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().uts_mode = Some("container:other".to_string());
        cases.push((inspect, DockerSecurityIncompleteReason::InvalidUtsMode));

        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().cgroupns_mode =
            Some(HostConfigCgroupnsModeEnum::EMPTY);
        cases.push((
            inspect,
            DockerSecurityIncompleteReason::AmbiguousCgroupnsMode,
        ));

        let mut inspect = valid_empty_risk_inspect();
        inspect.app_armor_profile = Some("unconfined\nignored".to_string());
        cases.push((
            inspect,
            DockerSecurityIncompleteReason::InvalidAppArmorProfile,
        ));

        for (inspect, expected) in cases {
            assert_incomplete(&evaluate(&inspect), expected);
        }
    }

    #[test]
    fn incomplete_bind_mount_facts_are_unknown() {
        let cases = [
            (
                MountPoint {
                    typ: None,
                    ..bind_mount()
                },
                DockerSecurityIncompleteReason::IncompleteMountType,
            ),
            (
                MountPoint {
                    source: None,
                    ..bind_mount()
                },
                DockerSecurityIncompleteReason::IncompleteBindSource,
            ),
            (
                MountPoint {
                    source: Some("relative/path".to_string()),
                    ..bind_mount()
                },
                DockerSecurityIncompleteReason::IncompleteBindSource,
            ),
            (
                MountPoint {
                    source: Some("/srv/../etc".to_string()),
                    ..bind_mount()
                },
                DockerSecurityIncompleteReason::IncompleteBindSource,
            ),
            (
                MountPoint {
                    destination: None,
                    ..bind_mount()
                },
                DockerSecurityIncompleteReason::IncompleteBindDestination,
            ),
            (
                MountPoint {
                    rw: None,
                    ..bind_mount()
                },
                DockerSecurityIncompleteReason::IncompleteBindWritable,
            ),
        ];

        for (mount, expected) in cases {
            let mut inspect = valid_empty_risk_inspect();
            inspect.mounts = Some(vec![mount]);
            assert_incomplete(&evaluate(&inspect), expected);
        }
    }

    #[test]
    fn proven_empty_risk_inspect_accepts_legitimate_nullable_lists() {
        let inspect = valid_empty_risk_inspect();
        let host_config = inspect.host_config.as_ref().unwrap();
        assert!(host_config.cap_add.is_none());
        assert!(host_config.security_opt.is_none());

        let outcome = evaluate(&inspect);
        assert!(outcome.risks.is_empty());
        assert!(outcome.incomplete_reasons.is_empty());

        for unsafe_type in ["spc_t", "unconfined_t"] {
            let mut unconfined = valid_empty_risk_inspect();
            unconfined.app_armor_profile = Some(String::new());
            unconfined.process_label = Some(format!("system_u:system_r:{unsafe_type}:s0:c1,c2"));
            let mut daemon = safe_daemon_security_facts();
            daemon.selinux = SecurityFact::Enabled;
            let outcome =
                DockerService::evaluate_inspect_security_risks(&unconfined, "fallback", daemon);
            assert!(outcome.risks.iter().any(|risk| {
                risk.severity == "high" && risk.finding == "Mandatory access control unconfined"
            }));
        }

        let mut unknown = valid_empty_risk_inspect();
        unknown.app_armor_profile = Some(String::new());
        unknown.process_label = Some("system_u:system_r:custom_container_t:s0:c1,c2".to_string());
        let mut daemon = safe_daemon_security_facts();
        daemon.selinux = SecurityFact::Enabled;
        let outcome = DockerService::evaluate_inspect_security_risks(&unknown, "fallback", daemon);
        assert!(outcome.risks.is_empty());
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::UnclassifiedSelinuxProcessLabel,
        );
    }

    #[test]
    fn proven_non_bind_type_does_not_require_bind_only_facts() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.mounts = Some(vec![MountPoint {
            typ: Some(MountPointTypeEnum::VOLUME),
            ..Default::default()
        }]);

        let outcome = evaluate(&inspect);
        assert!(outcome.risks.is_empty());
        assert!(outcome.incomplete_reasons.is_empty());
    }

    #[test]
    fn complete_sensitive_bind_mount_preserves_existing_risk_detection() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.mounts = Some(vec![MountPoint {
            source: Some("/etc".to_string()),
            rw: Some(true),
            ..bind_mount()
        }]);

        let outcome = evaluate(&inspect);
        assert!(outcome.incomplete_reasons.is_empty());
        assert_eq!(outcome.risks.len(), 1);
        assert_eq!(outcome.risks[0].finding, "Sensitive host bind mount");
        assert_eq!(outcome.risks[0].severity, "high");
        assert!(outcome.risks[0].evidence.contains("surface=host_config"));
        assert!(outcome.risks[0].evidence.contains("rw=true"));

        let mut home = valid_empty_risk_inspect();
        home.mounts = Some(vec![MountPoint {
            source: Some("/home/SECRET_MOUNT_SENTINEL".to_string()),
            destination: Some("/host/SECRET_TARGET_SENTINEL".to_string()),
            rw: Some(true),
            ..bind_mount()
        }]);
        let outcome = evaluate(&home);
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.evidence.contains("surface=user_homes"))
        );
        assert!(outcome.risks.iter().all(|risk| {
            !risk.evidence.contains("SECRET_MOUNT_SENTINEL")
                && !risk.evidence.contains("SECRET_TARGET_SENTINEL")
        }));

        let mut agent_state = valid_empty_risk_inspect();
        agent_state.mounts = Some(vec![MountPoint {
            source: Some("/var/lib/mini-ops/SECRET_DB_SENTINEL".to_string()),
            destination: Some("/state".to_string()),
            rw: Some(true),
            ..bind_mount()
        }]);
        let outcome = evaluate(&agent_state);
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.evidence.contains("surface=agent_state"))
        );
        assert!(
            outcome
                .risks
                .iter()
                .all(|risk| !risk.evidence.contains("SECRET_DB_SENTINEL"))
        );
    }

    #[test]
    fn explicit_capabilities_are_normalized_bounded_and_never_silently_safe() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().cap_add = Some(vec![
            "cap_sys_admin".to_string(),
            "CAP_BPF".to_string(),
            "NET_RAW".to_string(),
        ]);
        let outcome = evaluate(&inspect);
        assert!(outcome.incomplete_reasons.is_empty());
        assert!(outcome.risks.iter().any(|risk| {
            risk.severity == "critical" && risk.evidence.ends_with("cap_add=SYS_ADMIN")
        }));
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| { risk.severity == "high" && risk.evidence.ends_with("cap_add=BPF") })
        );
        assert!(outcome.risks.iter().any(|risk| {
            risk.severity == "medium" && risk.evidence.ends_with("cap_add=NET_RAW")
        }));

        for malformed in ["CAP_SYS_ADMIN\nSECRET", &"X".repeat(65)] {
            let mut inspect = valid_empty_risk_inspect();
            inspect.host_config.as_mut().unwrap().cap_add = Some(vec![malformed.to_string()]);
            let outcome = evaluate(&inspect);
            assert_incomplete(&outcome, DockerSecurityIncompleteReason::InvalidCapability);
            assert!(
                outcome
                    .risks
                    .iter()
                    .all(|risk| !risk.evidence.contains("SECRET"))
            );
        }
    }

    #[test]
    fn known_critical_risk_survives_incomplete_inspect_facts() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().privileged = Some(true);
        inspect.mounts = None;

        let outcome = evaluate(&inspect);
        assert!(
            outcome.risks.iter().any(|risk| {
                risk.severity == "critical" && risk.finding == "Privileged container"
            })
        );
        assert_incomplete(&outcome, DockerSecurityIncompleteReason::MissingMounts);
    }

    #[test]
    fn host_uts_namespace_is_a_known_high_risk() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().uts_mode = Some("host".to_string());
        let outcome = evaluate(&inspect);
        assert!(outcome.incomplete_reasons.is_empty());
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| { risk.severity == "high" && risk.finding == "Host UTS namespace" })
        );
    }

    #[test]
    fn explicit_host_device_mapping_is_a_known_high_risk_without_raw_paths() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().devices = Some(vec![DeviceMapping {
            path_on_host: Some("/dev/SECRET_DEVICE_SENTINEL".to_string()),
            path_in_container: Some("/dev/data".to_string()),
            cgroup_permissions: Some("rwm".to_string()),
        }]);
        let outcome = evaluate(&inspect);
        assert!(outcome.risks.iter().any(|risk| {
            risk.severity == "high"
                && risk.finding == "Host device mapping"
                && risk.evidence.contains("device_mapping_count=1")
        }));
        assert!(
            outcome
                .risks
                .iter()
                .all(|risk| !risk.evidence.contains("SECRET_DEVICE_SENTINEL"))
        );
    }

    #[test]
    fn bounded_merge_never_panics_or_discards_later_critical_risk() {
        let mut outcome = DockerSecurityAuditOutcome::default();
        outcome.merge(DockerSecurityAuditOutcome::default());
        assert!(outcome.risks.is_empty());

        outcome.risks = (0..MAX_DOCKER_SECURITY_RISKS)
            .map(|index| DockerSecurityRisk {
                severity: "medium".to_string(),
                finding: format!("medium-{index}"),
                evidence: "container=fixture".to_string(),
            })
            .collect();
        outcome.merge(DockerSecurityAuditOutcome {
            risks: vec![DockerSecurityRisk {
                severity: "critical".to_string(),
                finding: "later critical".to_string(),
                evidence: "container=later privileged=true".to_string(),
            }],
            incomplete_reasons: Vec::new(),
        });

        assert_eq!(outcome.risks.len(), MAX_DOCKER_SECURITY_RISKS);
        assert!(outcome.risks.iter().any(|risk| risk.severity == "critical"));
        assert_incomplete(&outcome, DockerSecurityIncompleteReason::RiskLimitExceeded);
    }

    #[test]
    fn security_options_normalize_current_and_legacy_separators() {
        for separator in ['=', ':'] {
            let options = vec![
                format!("seccomp{separator}builtin"),
                format!("apparmor{separator}docker-default"),
                format!("no-new-privileges{separator}true"),
            ];
            let parsed = parse_security_options(Some(&options));
            assert!(parsed.incomplete_reasons.is_empty());
            assert!(matches!(
                parsed.seccomp,
                OverrideState::Value(SecurityProfileOverride::KnownConfined(_))
            ));
            assert!(matches!(
                parsed.apparmor,
                OverrideState::Value(SecurityProfileOverride::KnownConfined(_))
            ));
            assert_eq!(parsed.no_new_privileges, OverrideState::Value(true));
        }

        let bare = vec!["no-new-privileges".to_string()];
        let parsed = parse_security_options(Some(&bare));
        assert!(parsed.incomplete_reasons.is_empty());
        assert_eq!(parsed.no_new_privileges, OverrideState::Value(true));
    }

    #[test]
    fn duplicate_conflicting_and_malformed_security_options_are_unknown() {
        let duplicate = vec!["seccomp=builtin".to_string(), "seccomp:builtin".to_string()];
        let parsed = parse_security_options(Some(&duplicate));
        assert_eq!(parsed.seccomp, OverrideState::Invalid);
        assert!(
            parsed
                .incomplete_reasons
                .contains(&DockerSecurityIncompleteReason::DuplicateSecurityOption)
        );

        let conflicting = vec![
            "no-new-privileges=true".to_string(),
            "no-new-privileges:false".to_string(),
        ];
        let parsed = parse_security_options(Some(&conflicting));
        assert_eq!(parsed.no_new_privileges, OverrideState::Invalid);
        assert!(
            parsed
                .incomplete_reasons
                .contains(&DockerSecurityIncompleteReason::ConflictingSecurityOption)
        );

        for malformed in [
            "seccomp==unconfined",
            "apparmor:",
            "no-new-privileges=maybe",
            "seccomp unconfined",
            "seccompé",
            "seccomp=unconfined=garbage",
            "seccomp:builtin:garbage",
        ] {
            let options = vec![malformed.to_string()];
            let parsed = parse_security_options(Some(&options));
            assert!(
                parsed
                    .incomplete_reasons
                    .contains(&DockerSecurityIncompleteReason::MalformedSecurityOption),
                "relevant malformed option must remain unknown: {malformed}"
            );
        }

        let unrelated_non_ascii = vec!["éééé".to_string()];
        let parsed = parse_security_options(Some(&unrelated_non_ascii));
        assert!(parsed.incomplete_reasons.is_empty());

        for custom in ["seccomp=/tmp/custom.json", "apparmor=custom-profile"] {
            let options = vec![custom.to_string()];
            let parsed = parse_security_options(Some(&options));
            assert!(
                parsed
                    .incomplete_reasons
                    .contains(&DockerSecurityIncompleteReason::UnclassifiedSecurityProfile)
            );
        }

        let mut tail_safe_override = (0..MAX_DOCKER_SECURITY_OPTIONS)
            .map(|index| format!("unrelated-{index}"))
            .collect::<Vec<_>>();
        tail_safe_override.push("seccomp=builtin".to_string());
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().security_opt = Some(tail_safe_override);
        let mut daemon_facts = safe_daemon_security_facts();
        daemon_facts.seccomp = SecurityFact::Disabled;
        let outcome =
            DockerService::evaluate_inspect_security_risks(&inspect, "fallback", daemon_facts);
        assert!(
            outcome
                .risks
                .iter()
                .all(|risk| risk.finding != "Seccomp disabled")
        );
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::SecurityOptionLimitExceeded,
        );

        let mut bounded_known_unsafe = vec!["seccomp=unconfined".to_string()];
        bounded_known_unsafe
            .extend((0..MAX_DOCKER_SECURITY_OPTIONS).map(|index| format!("unrelated-{index}")));
        inspect.host_config.as_mut().unwrap().security_opt = Some(bounded_known_unsafe);
        let outcome = evaluate(&inspect);
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.severity == "high" && risk.finding == "Seccomp disabled")
        );
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::SecurityOptionLimitExceeded,
        );
    }

    #[test]
    fn explicit_system_paths_unconfined_is_a_known_high_risk() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().security_opt =
            Some(vec!["systempaths=unconfined".to_string()]);
        let outcome = evaluate(&inspect);
        assert!(outcome.risks.iter().any(|risk| {
            risk.severity == "high" && risk.finding == "Container system paths unconfined"
        }));

        let mut effective_empty = valid_empty_risk_inspect();
        effective_empty.host_config.as_mut().unwrap().security_opt = None;
        effective_empty.host_config.as_mut().unwrap().masked_paths = Some(Vec::new());
        effective_empty.host_config.as_mut().unwrap().readonly_paths = Some(Vec::new());
        let outcome = evaluate(&effective_empty);
        assert!(outcome.risks.iter().any(|risk| {
            risk.severity == "high" && risk.finding == "Container system paths unconfined"
        }));

        let mut missing = valid_empty_risk_inspect();
        missing.host_config.as_mut().unwrap().masked_paths = None;
        let outcome = evaluate(&missing);
        assert_incomplete(&outcome, DockerSecurityIncompleteReason::MissingMaskedPaths);
    }

    #[test]
    fn daemon_security_facts_are_typed_and_fail_safe() {
        let enabled = vec![
            "name=apparmor".to_string(),
            "name=seccomp,profile=builtin".to_string(),
            "name=no-new-privileges".to_string(),
            "name=userns".to_string(),
            "name=selinux".to_string(),
        ];
        let facts = parse_daemon_security_options(Some(&enabled));
        assert_eq!(facts.seccomp, SecurityFact::Enabled);
        assert_eq!(facts.no_new_privileges, SecurityFact::Enabled);
        assert_eq!(facts.userns, SecurityFact::Enabled);
        assert_eq!(facts.selinux, SecurityFact::Enabled);

        let disabled = parse_daemon_security_options(Some(&[]));
        assert_eq!(disabled.seccomp, SecurityFact::Disabled);
        assert_eq!(disabled.no_new_privileges, SecurityFact::Disabled);
        assert_eq!(disabled.userns, SecurityFact::Disabled);
        assert_eq!(disabled.selinux, SecurityFact::Disabled);

        let missing = parse_daemon_security_options(None);
        for fact in [
            missing.seccomp,
            missing.no_new_privileges,
            missing.userns,
            missing.selinux,
        ] {
            assert_eq!(
                fact,
                SecurityFact::Unknown(DockerSecurityIncompleteReason::MissingDaemonSecurityOptions)
            );
        }

        for malformed in ["name=seccomp=garbage", "seccomp bogus", "name=userns:"] {
            let options = vec![malformed.to_string()];
            let facts = parse_daemon_security_options(Some(&options));
            let fact = if malformed.contains("userns") {
                facts.userns
            } else {
                facts.seccomp
            };
            assert_eq!(
                fact,
                SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidDaemonSecurityOption),
                "malformed daemon fact must remain unknown: {malformed}"
            );
        }

        let seccomp_extra = vec!["name=seccomp,profile=builtin,enabled=false".to_string()];
        assert_eq!(
            parse_daemon_security_options(Some(&seccomp_extra)).seccomp,
            SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidDaemonSecurityOption)
        );
        let nnp_extra = vec!["name=no-new-privileges,enabled=false".to_string()];
        assert_eq!(
            parse_daemon_security_options(Some(&nnp_extra)).no_new_privileges,
            SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidDaemonSecurityOption)
        );

        let custom = vec!["name=seccomp,profile=/tmp/custom.json".to_string()];
        assert_eq!(
            parse_daemon_security_options(Some(&custom)).seccomp,
            SecurityFact::Unknown(DockerSecurityIncompleteReason::UnclassifiedSecurityProfile)
        );

        let mut overflow_with_known_unsafe = vec!["name=seccomp,profile=unconfined".to_string()];
        overflow_with_known_unsafe.extend(
            (0..MAX_DOCKER_DAEMON_SECURITY_OPTIONS).map(|index| format!("name=apparmor-{index}")),
        );
        let facts = parse_daemon_security_options(Some(&overflow_with_known_unsafe));
        assert!(facts.option_limit_exceeded);
        assert!(facts.seccomp_unconfined_seen);
        let outcome = DockerService::evaluate_inspect_security_risks(
            &valid_empty_risk_inspect(),
            "fallback",
            facts,
        );
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.severity == "high" && risk.finding == "Seccomp disabled")
        );
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::DaemonSecurityOptionLimitExceeded,
        );

        let mut overflow_before_safe_seccomp = (0..MAX_DOCKER_DAEMON_SECURITY_OPTIONS)
            .map(|index| format!("name=apparmor-{index}"))
            .collect::<Vec<_>>();
        overflow_before_safe_seccomp.push("name=seccomp,profile=builtin".to_string());
        let facts = parse_daemon_security_options(Some(&overflow_before_safe_seccomp));
        assert_eq!(
            facts.seccomp,
            SecurityFact::Unknown(
                DockerSecurityIncompleteReason::DaemonSecurityOptionLimitExceeded
            )
        );
        let outcome = DockerService::evaluate_inspect_security_risks(
            &valid_empty_risk_inspect(),
            "fallback",
            facts,
        );
        assert!(
            outcome
                .risks
                .iter()
                .all(|risk| risk.finding != "Seccomp disabled")
        );
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::DaemonSecurityOptionLimitExceeded,
        );

        assert_eq!(parse_selinux_enforcement(b"1\n"), SecurityFact::Enabled);
        assert_eq!(parse_selinux_enforcement(b"0\n"), SecurityFact::Disabled);
        assert_eq!(
            parse_selinux_enforcement(b"permissive"),
            SecurityFact::Unknown(DockerSecurityIncompleteReason::InvalidSelinuxEnforcement)
        );
    }

    #[test]
    fn confinement_must_be_proven_by_container_or_daemon_facts() {
        let inspect = valid_empty_risk_inspect();
        let disabled_daemon = DockerDaemonSecurityFacts {
            seccomp: SecurityFact::Disabled,
            no_new_privileges: SecurityFact::Disabled,
            userns: SecurityFact::Disabled,
            selinux: SecurityFact::Disabled,
            seccomp_unconfined_seen: false,
            option_limit_exceeded: false,
        };
        let outcome =
            DockerService::evaluate_inspect_security_risks(&inspect, "fallback", disabled_daemon);
        assert!(outcome.incomplete_reasons.is_empty());

        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.finding == "Seccomp disabled" && risk.severity == "high")
        );
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.finding == "no-new-privileges disabled")
        );
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.finding == "Host user namespace")
        );

        let mut apparmor_with_unknown_selinux = safe_daemon_security_facts();
        apparmor_with_unknown_selinux.selinux =
            SecurityFact::Unknown(DockerSecurityIncompleteReason::SelinuxEnforcementUnavailable);
        let outcome = DockerService::evaluate_inspect_security_risks(
            &valid_empty_risk_inspect(),
            "fallback",
            apparmor_with_unknown_selinux,
        );
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::SelinuxEnforcementUnavailable,
        );

        let mut explicit = valid_empty_risk_inspect();
        explicit.host_config.as_mut().unwrap().security_opt = Some(vec![
            "seccomp=builtin".to_string(),
            "no-new-privileges:true".to_string(),
        ]);
        let outcome = DockerService::evaluate_inspect_security_risks(
            &explicit,
            "fallback",
            DockerDaemonSecurityFacts {
                seccomp: SecurityFact::Disabled,
                no_new_privileges: SecurityFact::Disabled,
                userns: SecurityFact::Enabled,
                selinux: SecurityFact::Disabled,
                seccomp_unconfined_seen: false,
                option_limit_exceeded: false,
            },
        );
        assert!(outcome.risks.is_empty());
        assert!(outcome.incomplete_reasons.is_empty());
    }

    #[test]
    fn empty_or_conflicting_apparmor_facts_cannot_pass() {
        let mut unconfined = valid_empty_risk_inspect();
        unconfined.app_armor_profile = Some(String::new());
        let outcome = evaluate(&unconfined);
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.finding == "Mandatory access control unconfined"
                    && risk.severity == "high")
        );

        let mut conflicting = valid_empty_risk_inspect();
        conflicting.host_config.as_mut().unwrap().security_opt =
            Some(vec!["apparmor=unconfined".to_string()]);
        let outcome = evaluate(&conflicting);
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::ConflictingAppArmorFacts,
        );
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.finding == "Mandatory access control unconfined")
        );

        let mut selinux_confined = valid_empty_risk_inspect();
        selinux_confined.app_armor_profile = Some(String::new());
        selinux_confined.process_label = Some("system_u:system_r:container_t:s0:c1,c2".to_string());
        let mut daemon = safe_daemon_security_facts();
        daemon.selinux = SecurityFact::Enabled;
        let outcome =
            DockerService::evaluate_inspect_security_risks(&selinux_confined, "fallback", daemon);
        assert!(outcome.risks.is_empty());
        assert!(outcome.incomplete_reasons.is_empty());

        let mut custom_apparmor = valid_empty_risk_inspect();
        custom_apparmor.app_armor_profile = Some("custom-profile".to_string());
        let outcome = evaluate(&custom_apparmor);
        assert!(outcome.risks.is_empty());
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::UnclassifiedSecurityProfile,
        );
    }

    #[test]
    fn conflicting_options_preserve_every_known_unsafe_fact() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.host_config.as_mut().unwrap().security_opt = Some(vec![
            "seccomp=unconfined".to_string(),
            "seccomp:builtin".to_string(),
            "no-new-privileges=false".to_string(),
            "no-new-privileges:true".to_string(),
            "apparmor=unconfined".to_string(),
            "apparmor:docker-default".to_string(),
        ]);
        let outcome = evaluate(&inspect);
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::ConflictingSecurityOption,
        );
        for finding in [
            "Seccomp disabled",
            "no-new-privileges disabled",
            "Mandatory access control unconfined",
        ] {
            assert!(
                outcome.risks.iter().any(|risk| risk.finding == finding),
                "known unsafe fact must survive conflict: {finding}"
            );
        }

        let daemon = vec![
            "name=seccomp,profile=unconfined".to_string(),
            "name=seccomp,profile=unconfined".to_string(),
        ];
        let daemon_facts = parse_daemon_security_options(Some(&daemon));
        assert!(daemon_facts.seccomp_unconfined_seen);
        let outcome = DockerService::evaluate_inspect_security_risks(
            &valid_empty_risk_inspect(),
            "fallback",
            daemon_facts,
        );
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.finding == "Seccomp disabled")
        );
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::DuplicateDaemonSecurityOption,
        );
    }

    #[test]
    fn malformed_container_identity_is_redacted_and_incomplete() {
        let mut inspect = valid_empty_risk_inspect();
        inspect.name = Some("/bad\nSECRET_SENTINEL".to_string());
        inspect.host_config.as_mut().unwrap().privileged = Some(true);

        let outcome = evaluate(&inspect);
        assert_incomplete(
            &outcome,
            DockerSecurityIncompleteReason::InvalidContainerIdentity,
        );
        assert!(
            outcome
                .risks
                .iter()
                .all(|risk| !risk.evidence.contains("SECRET_SENTINEL"))
        );
        assert!(
            outcome
                .risks
                .iter()
                .any(|risk| risk.evidence.contains("container=unknown"))
        );
    }

    #[test]
    fn container_identity_rejects_url_dot_segments() {
        assert!(!is_valid_container_target("."));
        assert!(!is_valid_container_target(".."));
        assert!(is_valid_container_target("safe.container-1_2"));
        assert!(is_valid_container_target(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn daemon_controlled_error_messages_are_never_relogged_or_returned() {
        let sentinel = "RAW_DOCKER_ERROR_SECRET_SENTINEL";
        let error = bollard::errors::Error::DockerResponseServerError {
            status_code: 500,
            message: sentinel.to_string(),
        };
        for code in [
            "docker_connection_failed",
            "docker_list_failed",
            "docker_action_failed",
            "docker_log_stream_failed",
        ] {
            let projected = closed_docker_error(&error, code);
            assert_eq!(projected, code);
            assert!(!projected.contains(sentinel));
        }
    }
}
