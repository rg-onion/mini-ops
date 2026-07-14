use chrono::Utc;
use futures_util::stream::{self, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier, verify_server_name};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, lookup_host};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{FromDer, X509Certificate};

pub(crate) const MAX_TARGETS: usize = 32;
pub(crate) const MAX_CONCURRENCY: usize = 8;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_DNS_ANSWERS: usize = 8;
const MAX_CHAIN_CERTIFICATES: usize = 8;
const MAX_CHAIN_BYTES: usize = 256 * 1024;
const MAX_LABEL_BYTES: usize = 128;
const MAX_ISSUER_BYTES: usize = 128;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TARGET_TIMEOUT: Duration = Duration::from_secs(10);
const DAY_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrustProfile {
    System,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CertificateTarget {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) connect_host: String,
    pub(crate) port: u16,
    pub(crate) server_name: String,
    pub(crate) trust_profile: TrustProfile,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CertificateTargetsConfig {
    pub(crate) schema_version: u64,
    pub(crate) targets: Vec<CertificateTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTargetsConfig {
    schema_version: u64,
    targets: Vec<RawCertificateTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCertificateTarget {
    id: String,
    label: String,
    connect_host: String,
    port: u16,
    server_name: String,
    trust_profile: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateConfigError {
    ConfigTooLarge,
    InvalidToml,
    UnsupportedSchema,
    InvalidTargetCount,
    InvalidTargetId,
    DuplicateTargetId,
    InvalidLabel,
    InvalidConnectHost,
    InvalidPort,
    InvalidServerName,
    UnsupportedTrustProfile,
}

impl CertificateConfigError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ConfigTooLarge => "config_too_large",
            Self::InvalidToml => "invalid_toml",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InvalidTargetCount => "invalid_target_count",
            Self::InvalidTargetId => "invalid_target_id",
            Self::DuplicateTargetId => "duplicate_target_id",
            Self::InvalidLabel => "invalid_label",
            Self::InvalidConnectHost => "invalid_connect_host",
            Self::InvalidPort => "invalid_port",
            Self::InvalidServerName => "invalid_server_name",
            Self::UnsupportedTrustProfile => "unsupported_trust_profile",
        }
    }
}

impl fmt::Display for CertificateConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CertificateConfigError {}

pub(crate) fn parse_targets_config(
    input: &[u8],
) -> Result<CertificateTargetsConfig, CertificateConfigError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(CertificateConfigError::ConfigTooLarge);
    }
    let input = std::str::from_utf8(input).map_err(|_| CertificateConfigError::InvalidToml)?;
    let raw: RawTargetsConfig =
        toml::from_str(input).map_err(|_| CertificateConfigError::InvalidToml)?;
    if raw.schema_version != 1 {
        return Err(CertificateConfigError::UnsupportedSchema);
    }
    if raw.targets.is_empty() || raw.targets.len() > MAX_TARGETS {
        return Err(CertificateConfigError::InvalidTargetCount);
    }

    let mut ids = BTreeSet::new();
    let mut targets = Vec::with_capacity(raw.targets.len());
    for raw_target in raw.targets {
        if !valid_target_id(&raw_target.id) {
            return Err(CertificateConfigError::InvalidTargetId);
        }
        if !ids.insert(raw_target.id.clone()) {
            return Err(CertificateConfigError::DuplicateTargetId);
        }
        if raw_target.label.is_empty()
            || raw_target.label.len() > MAX_LABEL_BYTES
            || raw_target.label.chars().any(char::is_control)
        {
            return Err(CertificateConfigError::InvalidLabel);
        }
        validate_host(&raw_target.connect_host)
            .map_err(|_| CertificateConfigError::InvalidConnectHost)?;
        if raw_target.port == 0 {
            return Err(CertificateConfigError::InvalidPort);
        }
        validate_server_name(&raw_target.server_name)
            .map_err(|_| CertificateConfigError::InvalidServerName)?;
        let trust_profile = match raw_target.trust_profile.as_str() {
            "system" => TrustProfile::System,
            _ => return Err(CertificateConfigError::UnsupportedTrustProfile),
        };
        targets.push(CertificateTarget {
            id: raw_target.id,
            label: raw_target.label,
            connect_host: raw_target.connect_host,
            port: raw_target.port,
            server_name: raw_target.server_name,
            trust_profile,
        });
    }

    Ok(CertificateTargetsConfig {
        schema_version: 1,
        targets,
    })
}

fn valid_target_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || (!bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit())
    {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    })
}

fn validate_host(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.len() > 253 {
        return Err(());
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if value
        .chars()
        .any(|character| matches!(character, '/' | '\\' | '@' | ':'))
    {
        return Err(());
    }
    validate_server_name(value)
}

fn validate_server_name(value: &str) -> Result<(), ()> {
    ServerName::try_from(value.to_owned())
        .map(|_| ())
        .map_err(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReachabilityStatus {
    Reachable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrustStatus {
    Valid,
    Invalid,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostnameStatus {
    Match,
    Mismatch,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExpiryStatus {
    Healthy,
    Warning,
    Critical,
    Expired,
    NotYetValid,
    Unknown,
}

impl ExpiryStatus {
    const fn currently_valid(self) -> bool {
        matches!(self, Self::Healthy | Self::Warning | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateProbeErrorCode {
    DnsTimeout,
    DnsFailed,
    ConnectTimeout,
    ConnectRefused,
    ConnectFailed,
    TlsTimeout,
    TlsHandshakeFailed,
    CertificateMissing,
    CertificateParseFailed,
    UnsupportedProtocol,
    Cancelled,
    InternalError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CertificateObservation {
    pub(crate) schema_version: u64,
    pub(crate) target_id: String,
    pub(crate) label: String,
    pub(crate) connect_host: String,
    pub(crate) port: u16,
    pub(crate) server_name: String,
    pub(crate) checked_at: i64,
    pub(crate) duration_ms: u64,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) reachability: ReachabilityStatus,
    pub(crate) trust: TrustStatus,
    pub(crate) hostname: HostnameStatus,
    pub(crate) expiry: ExpiryStatus,
    pub(crate) not_before: Option<i64>,
    pub(crate) not_after: Option<i64>,
    pub(crate) lifetime_seconds: Option<i64>,
    pub(crate) remaining_seconds: Option<i64>,
    pub(crate) issuer_organization: Option<String>,
    pub(crate) fingerprint_sha256_short: Option<String>,
    pub(crate) error_code: Option<CertificateProbeErrorCode>,
}

impl CertificateObservation {
    fn failure(
        target: &CertificateTarget,
        checked_at: i64,
        duration_ms: u64,
        reachability: ReachabilityStatus,
        error_code: CertificateProbeErrorCode,
    ) -> Self {
        Self {
            schema_version: 1,
            target_id: target.id.clone(),
            label: target.label.clone(),
            connect_host: target.connect_host.clone(),
            port: target.port,
            server_name: target.server_name.clone(),
            checked_at,
            duration_ms,
            last_success_at: None,
            reachability,
            trust: TrustStatus::Unknown,
            hostname: HostnameStatus::Unknown,
            expiry: ExpiryStatus::Unknown,
            not_before: None,
            not_after: None,
            lifetime_seconds: None,
            remaining_seconds: None,
            issuer_organization: None,
            fingerprint_sha256_short: None,
            error_code: Some(error_code),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateProbeInitError {
    SystemTrustUnavailable,
    TlsConfiguration,
}

impl CertificateProbeInitError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::SystemTrustUnavailable => "system_trust_unavailable",
            Self::TlsConfiguration => "tls_configuration",
        }
    }
}

impl fmt::Display for CertificateProbeInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CertificateProbeInitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateBatchError {
    InvalidTargetCount,
    InvalidConcurrency,
}

impl CertificateBatchError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidTargetCount => "invalid_target_count",
            Self::InvalidConcurrency => "invalid_concurrency",
        }
    }
}

impl fmt::Display for CertificateBatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CertificateBatchError {}

type ResolverFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

trait AddressResolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolverFuture<'a>;
}

#[derive(Debug)]
struct TokioAddressResolver;

impl AddressResolver for TokioAddressResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolverFuture<'a> {
        Box::pin(async move {
            let mut addresses = Vec::new();
            for address in lookup_host((host, port)).await? {
                if !addresses.contains(&address) {
                    addresses.push(address);
                    if addresses.len() == MAX_DNS_ANSWERS {
                        break;
                    }
                }
            }
            Ok(addresses)
        })
    }
}

#[derive(Clone)]
pub(crate) struct CertificateProbe {
    tls_connector: TlsConnector,
    trust_verifier: Arc<dyn ServerCertVerifier>,
    resolver: Arc<dyn AddressResolver>,
    timeouts: ProbeTimeouts,
}

#[derive(Clone, Copy)]
struct ProbeTimeouts {
    dns: Duration,
    connect: Duration,
    target: Duration,
}

impl Default for ProbeTimeouts {
    fn default() -> Self {
        Self {
            dns: DNS_TIMEOUT,
            connect: CONNECT_TIMEOUT,
            target: TARGET_TIMEOUT,
        }
    }
}

impl CertificateProbe {
    pub(crate) fn new_system() -> Result<Self, CertificateProbeInitError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            return Err(CertificateProbeInitError::SystemTrustUnavailable);
        }
        let mut roots = RootCertStore::empty();
        let (_, ignored) = roots.add_parsable_certificates(native.certs);
        if roots.is_empty() || ignored > 0 {
            return Err(CertificateProbeInitError::SystemTrustUnavailable);
        }
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|_| CertificateProbeInitError::SystemTrustUnavailable)?;
        Self::new_with_parts(
            provider,
            verifier,
            Arc::new(TokioAddressResolver),
            ProbeTimeouts::default(),
        )
    }

    fn new_with_parts(
        provider: Arc<CryptoProvider>,
        trust_verifier: Arc<dyn ServerCertVerifier>,
        resolver: Arc<dyn AddressResolver>,
        timeouts: ProbeTimeouts,
    ) -> Result<Self, CertificateProbeInitError> {
        let observation_verifier = Arc::new(ObservationOnlyVerifier {
            supported: provider.signature_verification_algorithms,
        });
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| CertificateProbeInitError::TlsConfiguration)?;
        let mut config = builder
            .dangerous()
            .with_custom_certificate_verifier(observation_verifier)
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.alpn_protocols.clear();
        Ok(Self {
            tls_connector: TlsConnector::from(Arc::new(config)),
            trust_verifier,
            resolver,
            timeouts,
        })
    }

    pub(crate) async fn probe(&self, target: &CertificateTarget) -> CertificateObservation {
        let checked_at = Utc::now().timestamp();
        let started = Instant::now();
        let deadline = started + self.timeouts.target;
        let outcome = self.probe_inner(target, checked_at, deadline).await;
        let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        match outcome {
            Ok(mut observation) => {
                observation.duration_ms = duration_ms;
                observation
            }
            Err(failure) => CertificateObservation::failure(
                target,
                checked_at,
                duration_ms,
                failure.reachability,
                failure.error_code,
            ),
        }
    }

    pub(crate) async fn probe_all(
        &self,
        targets: &[CertificateTarget],
        concurrency: usize,
    ) -> Result<Vec<CertificateObservation>, CertificateBatchError> {
        if targets.is_empty() || targets.len() > MAX_TARGETS {
            return Err(CertificateBatchError::InvalidTargetCount);
        }
        if concurrency == 0 || concurrency > MAX_CONCURRENCY {
            return Err(CertificateBatchError::InvalidConcurrency);
        }

        let mut observations: Vec<(usize, CertificateObservation)> =
            stream::iter(targets.iter().cloned().enumerate())
                .map(|(index, target)| {
                    let probe = self.clone();
                    async move { (index, probe.probe(&target).await) }
                })
                .buffer_unordered(concurrency)
                .collect()
                .await;
        observations.sort_by_key(|(index, _)| *index);
        Ok(observations
            .into_iter()
            .map(|(_, observation)| observation)
            .collect())
    }

    async fn probe_inner(
        &self,
        target: &CertificateTarget,
        checked_at: i64,
        deadline: Instant,
    ) -> Result<CertificateObservation, ProbeFailure> {
        let dns_deadline = std::cmp::min(deadline, Instant::now() + self.timeouts.dns);
        let addresses = match timeout_at(
            dns_deadline,
            self.resolver.resolve(&target.connect_host, target.port),
        )
        .await
        {
            Ok(Ok(addresses)) if !addresses.is_empty() => addresses,
            Ok(Ok(_)) | Ok(Err(_)) => {
                return Err(ProbeFailure::unknown(CertificateProbeErrorCode::DnsFailed));
            }
            Err(_) => {
                return Err(ProbeFailure::unknown(CertificateProbeErrorCode::DnsTimeout));
            }
        };

        let mut saw_timeout = false;
        let mut saw_refused = false;
        let mut connected = None;
        for mut address in addresses.into_iter().take(MAX_DNS_ANSWERS) {
            address.set_port(target.port);
            let connect_deadline = std::cmp::min(deadline, Instant::now() + self.timeouts.connect);
            match timeout_at(connect_deadline, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => {
                    connected = Some(stream);
                    break;
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    saw_refused = true;
                }
                Ok(Err(_)) => {}
                Err(_) => saw_timeout = true,
            }
        }
        let stream = match connected {
            Some(stream) => stream,
            None if saw_timeout => {
                return Err(ProbeFailure::unknown(
                    CertificateProbeErrorCode::ConnectTimeout,
                ));
            }
            None if saw_refused => {
                return Err(ProbeFailure::unknown(
                    CertificateProbeErrorCode::ConnectRefused,
                ));
            }
            None => {
                return Err(ProbeFailure::unknown(
                    CertificateProbeErrorCode::ConnectFailed,
                ));
            }
        };

        let server_name = ServerName::try_from(target.server_name.clone())
            .map_err(|_| ProbeFailure::reachable(CertificateProbeErrorCode::InternalError))?;
        let tls_stream = match timeout_at(
            deadline,
            self.tls_connector.connect(server_name.clone(), stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => {
                return Err(ProbeFailure::reachable(
                    CertificateProbeErrorCode::TlsHandshakeFailed,
                ));
            }
            Err(_) => {
                return Err(ProbeFailure::reachable(
                    CertificateProbeErrorCode::TlsTimeout,
                ));
            }
        };
        let certificates = tls_stream.get_ref().1.peer_certificates().ok_or_else(|| {
            ProbeFailure::reachable(CertificateProbeErrorCode::CertificateMissing)
        })?;
        evaluate_certificates(
            target,
            checked_at,
            server_name,
            certificates,
            self.trust_verifier.as_ref(),
        )
        .map_err(ProbeFailure::reachable)
    }
}

#[derive(Clone, Copy, Debug)]
struct ProbeFailure {
    reachability: ReachabilityStatus,
    error_code: CertificateProbeErrorCode,
}

impl ProbeFailure {
    const fn unknown(error_code: CertificateProbeErrorCode) -> Self {
        Self {
            reachability: ReachabilityStatus::Unknown,
            error_code,
        }
    }

    const fn reachable(error_code: CertificateProbeErrorCode) -> Self {
        Self {
            reachability: ReachabilityStatus::Reachable,
            error_code,
        }
    }
}

#[derive(Debug)]
struct ObservationOnlyVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ObservationOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if intermediates.len().saturating_add(1) > MAX_CHAIN_CERTIFICATES {
            return Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let total_bytes = intermediates
            .iter()
            .try_fold(end_entity.as_ref().len(), |total, certificate| {
                total.checked_add(certificate.as_ref().len())
            })
            .filter(|total| *total <= MAX_CHAIN_BYTES);
        if total_bytes.is_none() {
            return Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

fn evaluate_certificates(
    target: &CertificateTarget,
    checked_at: i64,
    server_name: ServerName<'static>,
    certificates: &[CertificateDer<'static>],
    trust_verifier: &dyn ServerCertVerifier,
) -> Result<CertificateObservation, CertificateProbeErrorCode> {
    if certificates.is_empty() {
        return Err(CertificateProbeErrorCode::CertificateMissing);
    }
    if certificates.len() > MAX_CHAIN_CERTIFICATES
        || certificates
            .iter()
            .try_fold(0_usize, |total, certificate| {
                total.checked_add(certificate.as_ref().len())
            })
            .is_none_or(|total| total > MAX_CHAIN_BYTES)
    {
        return Err(CertificateProbeErrorCode::CertificateParseFailed);
    }

    let leaf = &certificates[0];
    let parsed_certificate = ParsedCertificate::try_from(leaf)
        .map_err(|_| CertificateProbeErrorCode::CertificateParseFailed)?;
    let (remainder, x509) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|_| CertificateProbeErrorCode::CertificateParseFailed)?;
    if !remainder.is_empty() {
        return Err(CertificateProbeErrorCode::CertificateParseFailed);
    }
    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();
    let lifetime_seconds = not_after
        .checked_sub(not_before)
        .filter(|lifetime| *lifetime > 0)
        .ok_or(CertificateProbeErrorCode::CertificateParseFailed)?;
    let remaining_seconds = not_after.saturating_sub(checked_at);
    let expiry = expiry_status(checked_at, not_before, not_after, lifetime_seconds);
    let hostname = if verify_server_name(&parsed_certificate, &server_name).is_ok() {
        HostnameStatus::Match
    } else {
        HostnameStatus::Mismatch
    };
    let now = u64::try_from(checked_at)
        .map(|seconds| UnixTime::since_unix_epoch(Duration::from_secs(seconds)))
        .map_err(|_| CertificateProbeErrorCode::InternalError)?;
    let system_result =
        trust_verifier.verify_server_cert(leaf, &certificates[1..], &server_name, &[], now);
    let trust = classify_trust(system_result, hostname, expiry);
    let issuer_organization = x509
        .issuer()
        .iter_organization()
        .find_map(|attribute| attribute.as_str().ok())
        .and_then(|value| bounded_public_text(value, MAX_ISSUER_BYTES));

    Ok(CertificateObservation {
        schema_version: 1,
        target_id: target.id.clone(),
        label: target.label.clone(),
        connect_host: target.connect_host.clone(),
        port: target.port,
        server_name: target.server_name.clone(),
        checked_at,
        duration_ms: 0,
        last_success_at: Some(checked_at),
        reachability: ReachabilityStatus::Reachable,
        trust,
        hostname,
        expiry,
        not_before: Some(not_before),
        not_after: Some(not_after),
        lifetime_seconds: Some(lifetime_seconds),
        remaining_seconds: Some(remaining_seconds),
        issuer_organization,
        fingerprint_sha256_short: Some(short_fingerprint(leaf.as_ref())),
        error_code: None,
    })
}

fn classify_trust(
    result: Result<ServerCertVerified, TlsError>,
    hostname: HostnameStatus,
    expiry: ExpiryStatus,
) -> TrustStatus {
    let independently_valid = hostname == HostnameStatus::Match && expiry.currently_valid();
    match result {
        Ok(_) if independently_valid => TrustStatus::Valid,
        Err(TlsError::InvalidCertificate(error))
            if independently_valid && definitive_trust_failure(&error) =>
        {
            TrustStatus::Invalid
        }
        _ => TrustStatus::Unknown,
    }
}

fn definitive_trust_failure(error: &CertificateError) -> bool {
    matches!(
        error,
        CertificateError::BadEncoding
            | CertificateError::Revoked
            | CertificateError::UnhandledCriticalExtension
            | CertificateError::UnknownIssuer
            | CertificateError::BadSignature
            | CertificateError::InvalidPurpose
            | CertificateError::InvalidPurposeContext { .. }
    )
}

fn expiry_status(now: i64, not_before: i64, not_after: i64, lifetime_seconds: i64) -> ExpiryStatus {
    if now < not_before {
        return ExpiryStatus::NotYetValid;
    }
    if now >= not_after {
        return ExpiryStatus::Expired;
    }
    let remaining = not_after - now;
    let warning = adaptive_threshold(lifetime_seconds, 20, DAY_SECONDS, 30 * DAY_SECONDS);
    let critical = adaptive_threshold(lifetime_seconds, 10, 6 * 60 * 60, 7 * DAY_SECONDS);
    if remaining <= critical {
        ExpiryStatus::Critical
    } else if remaining <= warning {
        ExpiryStatus::Warning
    } else {
        ExpiryStatus::Healthy
    }
}

fn adaptive_threshold(lifetime: i64, percent: i64, floor: i64, ceiling: i64) -> i64 {
    let proportional = (i128::from(lifetime) * i128::from(percent) / 100)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    proportional.max(floor).min(ceiling)
}

fn bounded_public_text(value: &str, max_bytes: usize) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    let mut output = String::new();
    for character in value.chars() {
        if output.len().saturating_add(character.len_utf8()) > max_bytes {
            break;
        }
        output.push(character);
    }
    (!output.is_empty()).then_some(output)
}

fn short_fingerprint(certificate: &[u8]) -> String {
    let digest = Sha256::digest(certificate);
    let mut output = String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, date_time_ymd,
    };
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::ResolvesServerCertUsingSni;
    use rustls::sign::CertifiedKey;
    use rustls::{RootCertStore, ServerConfig};
    use std::future::pending;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsAcceptor;

    const VALID_CONFIG: &str = r#"
schema_version = 1

[[targets]]
id = "customer-api"
label = "Customer API"
connect_host = "203.0.113.10"
port = 443
server_name = "api.example.com"
trust_profile = "system"
"#;

    #[derive(Clone, Copy)]
    enum TestValidity {
        Current,
        Expired,
        NotYetValid,
    }

    struct IssuedCertificate {
        chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        root: CertificateDer<'static>,
    }

    enum ResolverBehavior {
        Addresses(Vec<SocketAddr>),
        Failure,
        Pending,
    }

    struct TestResolver {
        behavior: ResolverBehavior,
    }

    struct CountingResolver {
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
        started: Arc<Notify>,
        delay: Duration,
    }

    struct ActiveResolution(Arc<AtomicUsize>);

    impl Drop for ActiveResolution {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl AddressResolver for TestResolver {
        fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolverFuture<'a> {
            Box::pin(async move {
                match &self.behavior {
                    ResolverBehavior::Addresses(addresses) => Ok(addresses.clone()),
                    ResolverBehavior::Failure => {
                        Err(io::Error::new(io::ErrorKind::NotFound, "test resolver"))
                    }
                    ResolverBehavior::Pending => pending().await,
                }
            })
        }
    }

    impl AddressResolver for CountingResolver {
        fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolverFuture<'a> {
            Box::pin(async move {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.maximum.fetch_max(active, Ordering::SeqCst);
                let _guard = ActiveResolution(Arc::clone(&self.active));
                self.started.notify_one();
                tokio::time::sleep(self.delay).await;
                Ok(Vec::new())
            })
        }
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    fn issue_certificate(
        server_name: &str,
        validity: TestValidity,
        self_signed: bool,
    ) -> IssuedCertificate {
        let ca_key = KeyPair::generate().expect("test CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("test CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "Mini-Ops Test CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_certificate = ca_params.self_signed(&ca_key).expect("test CA certificate");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let leaf_key = KeyPair::generate().expect("test leaf key");
        let mut leaf_params =
            CertificateParams::new(vec![server_name.to_owned()]).expect("test leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, "Mini-Ops Test Service");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, server_name);
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        match validity {
            TestValidity::Current => {
                leaf_params.not_before = date_time_ymd(2020, 1, 1);
                leaf_params.not_after = date_time_ymd(2090, 1, 1);
            }
            TestValidity::Expired => {
                leaf_params.not_before = date_time_ymd(1999, 1, 1);
                leaf_params.not_after = date_time_ymd(2000, 1, 1);
            }
            TestValidity::NotYetValid => {
                leaf_params.not_before = date_time_ymd(3000, 1, 1);
                leaf_params.not_after = date_time_ymd(3001, 1, 1);
            }
        }
        let leaf_certificate = if self_signed {
            leaf_params
                .self_signed(&leaf_key)
                .expect("self-signed test leaf")
        } else {
            leaf_params
                .signed_by(&leaf_key, &issuer)
                .expect("CA-signed test leaf")
        };
        let mut chain = vec![leaf_certificate.der().clone()];
        if !self_signed {
            chain.push(ca_certificate.der().clone());
        }

        IssuedCertificate {
            chain,
            private_key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
            root: ca_certificate.der().clone(),
        }
    }

    fn verifier_for_root(
        root: CertificateDer<'static>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Arc<dyn ServerCertVerifier> {
        let mut roots = RootCertStore::empty();
        roots.add(root).expect("test root");
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider)
            .build()
            .expect("test verifier")
    }

    fn server_config(
        issued: IssuedCertificate,
        crypto_provider: Arc<CryptoProvider>,
        require_sni: bool,
    ) -> (ServerConfig, Arc<dyn ServerCertVerifier>) {
        let trust_verifier = verifier_for_root(issued.root, Arc::clone(&crypto_provider));
        let builder = ServerConfig::builder_with_provider(Arc::clone(&crypto_provider))
            .with_safe_default_protocol_versions()
            .expect("test protocol versions")
            .with_no_client_auth();
        let config = if require_sni {
            let certified_key =
                CertifiedKey::from_der(issued.chain, issued.private_key, &crypto_provider)
                    .expect("test certified key");
            let mut resolver = ResolvesServerCertUsingSni::new();
            resolver
                .add("service.test", certified_key)
                .expect("test SNI certificate");
            builder.with_cert_resolver(Arc::new(resolver))
        } else {
            builder
                .with_single_cert(issued.chain, issued.private_key)
                .expect("test server certificate")
        };
        (config, trust_verifier)
    }

    async fn start_tls_server(config: ServerConfig) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("test listener address");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });
        (address, handle)
    }

    async fn start_plaintext_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("test listener address");
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"not tls\n").await;
            }
        });
        (address, handle)
    }

    async fn start_stalled_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("test listener address");
        let handle = tokio::spawn(async move {
            if let Ok((_stream, _)) = listener.accept().await {
                pending::<()>().await;
            }
        });
        (address, handle)
    }

    fn default_timeouts() -> ProbeTimeouts {
        ProbeTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(1),
            target: Duration::from_secs(2),
        }
    }

    fn test_probe(
        trust_verifier: Arc<dyn ServerCertVerifier>,
        resolver: Arc<dyn AddressResolver>,
        timeouts: ProbeTimeouts,
    ) -> CertificateProbe {
        CertificateProbe::new_with_parts(provider(), trust_verifier, resolver, timeouts)
            .expect("test probe")
    }

    fn target(port: u16, server_name: &str) -> CertificateTarget {
        CertificateTarget {
            id: "service".to_owned(),
            label: "Service".to_owned(),
            connect_host: "127.0.0.1".to_owned(),
            port,
            server_name: server_name.to_owned(),
            trust_profile: TrustProfile::System,
        }
    }

    #[test]
    fn config_parser_accepts_strict_versioned_targets() {
        let config = parse_targets_config(VALID_CONFIG.as_bytes()).expect("valid config");

        assert_eq!(config.schema_version, 1);
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].id, "customer-api");
        assert_eq!(config.targets[0].port, 443);
        assert_eq!(config.targets[0].trust_profile, TrustProfile::System);
    }

    #[test]
    fn config_parser_rejects_unknown_fields_and_unsupported_values() {
        let cases = [
            (
                VALID_CONFIG.replace(
                    "trust_profile = \"system\"",
                    "trust_profile = \"system\"\nextra = true",
                ),
                CertificateConfigError::InvalidToml,
            ),
            (
                VALID_CONFIG.replace("schema_version = 1", "schema_version = 2"),
                CertificateConfigError::UnsupportedSchema,
            ),
            (
                VALID_CONFIG.replace("trust_profile = \"system\"", "trust_profile = \"insecure\""),
                CertificateConfigError::UnsupportedTrustProfile,
            ),
            (
                VALID_CONFIG.replace("port = 443", "port = 0"),
                CertificateConfigError::InvalidPort,
            ),
            (
                VALID_CONFIG.replace("id = \"customer-api\"", "id = \"Customer/Api\""),
                CertificateConfigError::InvalidTargetId,
            ),
            (
                VALID_CONFIG.replace(
                    "connect_host = \"203.0.113.10\"",
                    "connect_host = \"https://example.com\"",
                ),
                CertificateConfigError::InvalidConnectHost,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(parse_targets_config(input.as_bytes()), Err(expected));
        }
    }

    #[test]
    fn config_parser_enforces_size_count_and_unique_ids() {
        assert_eq!(
            parse_targets_config(&vec![b' '; MAX_CONFIG_BYTES + 1]),
            Err(CertificateConfigError::ConfigTooLarge)
        );

        let duplicate = format!(
            "{VALID_CONFIG}\n[[targets]]{}",
            VALID_CONFIG
                .split("[[targets]]")
                .nth(1)
                .expect("target block")
        );
        assert_eq!(
            parse_targets_config(duplicate.as_bytes()),
            Err(CertificateConfigError::DuplicateTargetId)
        );

        let mut too_many = String::from("schema_version = 1\n");
        for index in 0..=MAX_TARGETS {
            let _ = write!(
                too_many,
                "\n[[targets]]\nid = \"target-{index}\"\nlabel = \"Target {index}\"\nconnect_host = \"127.0.0.1\"\nport = 443\nserver_name = \"example.com\"\ntrust_profile = \"system\"\n"
            );
        }
        assert_eq!(
            parse_targets_config(too_many.as_bytes()),
            Err(CertificateConfigError::InvalidTargetCount)
        );
    }

    #[test]
    fn adaptive_expiry_thresholds_cover_long_and_short_certificates() {
        assert_eq!(
            adaptive_threshold(90 * DAY_SECONDS, 20, DAY_SECONDS, 30 * DAY_SECONDS),
            18 * DAY_SECONDS
        );
        assert_eq!(
            adaptive_threshold(90 * DAY_SECONDS, 10, 6 * 60 * 60, 7 * DAY_SECONDS),
            7 * DAY_SECONDS
        );
        assert_eq!(
            adaptive_threshold(24 * 60 * 60, 20, DAY_SECONDS, 30 * DAY_SECONDS),
            DAY_SECONDS
        );
        assert_eq!(
            adaptive_threshold(24 * 60 * 60, 10, 6 * 60 * 60, 7 * DAY_SECONDS),
            6 * 60 * 60
        );
    }

    #[test]
    fn expiry_status_distinguishes_all_boundaries() {
        let lifetime = 90 * DAY_SECONDS;
        let not_before = 1_000_000;
        let not_after = not_before + lifetime;

        assert_eq!(
            expiry_status(not_before - 1, not_before, not_after, lifetime),
            ExpiryStatus::NotYetValid
        );
        assert_eq!(
            expiry_status(not_after, not_before, not_after, lifetime),
            ExpiryStatus::Expired
        );
        assert_eq!(
            expiry_status(not_after - 6 * DAY_SECONDS, not_before, not_after, lifetime),
            ExpiryStatus::Critical
        );
        assert_eq!(
            expiry_status(
                not_after - 10 * DAY_SECONDS,
                not_before,
                not_after,
                lifetime
            ),
            ExpiryStatus::Warning
        );
        assert_eq!(
            expiry_status(
                not_after - 40 * DAY_SECONDS,
                not_before,
                not_after,
                lifetime
            ),
            ExpiryStatus::Healthy
        );
    }

    #[test]
    fn trust_classification_keeps_ambiguous_errors_unknown() {
        assert_eq!(
            classify_trust(
                Ok(ServerCertVerified::assertion()),
                HostnameStatus::Match,
                ExpiryStatus::Healthy
            ),
            TrustStatus::Valid
        );
        assert_eq!(
            classify_trust(
                Ok(ServerCertVerified::assertion()),
                HostnameStatus::Mismatch,
                ExpiryStatus::Healthy
            ),
            TrustStatus::Unknown
        );
        assert_eq!(
            classify_trust(
                Err(TlsError::InvalidCertificate(
                    CertificateError::UnknownIssuer
                )),
                HostnameStatus::Match,
                ExpiryStatus::Healthy
            ),
            TrustStatus::Invalid
        );
        assert_eq!(
            classify_trust(
                Err(TlsError::General("test internal failure".to_owned())),
                HostnameStatus::Match,
                ExpiryStatus::Healthy
            ),
            TrustStatus::Unknown
        );
        assert_eq!(
            classify_trust(
                Err(TlsError::InvalidCertificate(CertificateError::Expired)),
                HostnameStatus::Match,
                ExpiryStatus::Healthy
            ),
            TrustStatus::Unknown
        );
        assert_eq!(
            classify_trust(
                Err(TlsError::InvalidCertificate(
                    CertificateError::UnsupportedSignatureAlgorithmContext {
                        signature_algorithm_id: Vec::new(),
                        supported_algorithms: Vec::new(),
                    },
                )),
                HostnameStatus::Match,
                ExpiryStatus::Healthy
            ),
            TrustStatus::Unknown
        );
    }

    #[tokio::test]
    async fn probe_uses_server_name_for_sni_and_returns_bounded_metadata() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, false);
        let (config, verifier) = server_config(issued, crypto_provider, true);
        let (address, server) = start_tls_server(config).await;
        let probe = test_probe(verifier, Arc::new(TokioAddressResolver), default_timeouts());

        let observation = probe.probe(&target(address.port(), "service.test")).await;
        let _ = server.await;

        assert_eq!(observation.reachability, ReachabilityStatus::Reachable);
        assert_eq!(observation.trust, TrustStatus::Valid);
        assert_eq!(observation.hostname, HostnameStatus::Match);
        assert_eq!(observation.expiry, ExpiryStatus::Healthy);
        assert_eq!(
            observation.issuer_organization.as_deref(),
            Some("Mini-Ops Test CA")
        );
        assert_eq!(
            observation
                .fingerprint_sha256_short
                .as_deref()
                .map(str::len),
            Some(16)
        );
        assert_eq!(observation.last_success_at, Some(observation.checked_at));
        assert_eq!(observation.error_code, None);
    }

    #[tokio::test]
    async fn probe_marks_hostname_mismatch_as_unknown_trust() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, false);
        let (config, verifier) = server_config(issued, crypto_provider, false);
        let (address, server) = start_tls_server(config).await;
        let probe = test_probe(verifier, Arc::new(TokioAddressResolver), default_timeouts());

        let observation = probe.probe(&target(address.port(), "other.test")).await;
        let _ = server.await;

        assert_eq!(observation.hostname, HostnameStatus::Mismatch);
        assert_eq!(observation.trust, TrustStatus::Unknown);
        assert_eq!(observation.expiry, ExpiryStatus::Healthy);
        assert_eq!(observation.error_code, None);
    }

    #[tokio::test]
    async fn probe_observes_expired_and_not_yet_valid_certificates() {
        for (validity, expected) in [
            (TestValidity::Expired, ExpiryStatus::Expired),
            (TestValidity::NotYetValid, ExpiryStatus::NotYetValid),
        ] {
            let crypto_provider = provider();
            let issued = issue_certificate("service.test", validity, false);
            let (config, verifier) = server_config(issued, crypto_provider, false);
            let (address, server) = start_tls_server(config).await;
            let probe = test_probe(verifier, Arc::new(TokioAddressResolver), default_timeouts());

            let observation = probe.probe(&target(address.port(), "service.test")).await;
            let _ = server.await;

            assert_eq!(observation.reachability, ReachabilityStatus::Reachable);
            assert_eq!(observation.hostname, HostnameStatus::Match);
            assert_eq!(observation.trust, TrustStatus::Unknown);
            assert_eq!(observation.expiry, expected);
            assert!(observation.not_after.is_some());
            assert_eq!(observation.error_code, None);
        }
    }

    #[tokio::test]
    async fn probe_marks_current_self_signed_certificate_invalid() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, true);
        let (config, verifier) = server_config(issued, crypto_provider, false);
        let (address, server) = start_tls_server(config).await;
        let probe = test_probe(verifier, Arc::new(TokioAddressResolver), default_timeouts());

        let observation = probe.probe(&target(address.port(), "service.test")).await;
        let _ = server.await;

        assert_eq!(observation.hostname, HostnameStatus::Match);
        assert_eq!(observation.trust, TrustStatus::Invalid);
        assert_eq!(observation.expiry, ExpiryStatus::Healthy);
    }

    #[tokio::test]
    async fn probe_classifies_dns_connect_and_tls_failures_without_false_passes() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, false);
        let verifier = verifier_for_root(issued.root, Arc::clone(&crypto_provider));
        let dns_probe = test_probe(
            Arc::clone(&verifier),
            Arc::new(TestResolver {
                behavior: ResolverBehavior::Failure,
            }),
            default_timeouts(),
        );
        let dns_observation = dns_probe.probe(&target(443, "service.test")).await;
        assert_eq!(dns_observation.reachability, ReachabilityStatus::Unknown);
        assert_eq!(dns_observation.trust, TrustStatus::Unknown);
        assert_eq!(
            dns_observation.error_code,
            Some(CertificateProbeErrorCode::DnsFailed)
        );

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("temporary listener");
        let refused_port = listener.local_addr().expect("temporary address").port();
        drop(listener);
        let connect_probe = test_probe(
            Arc::clone(&verifier),
            Arc::new(TokioAddressResolver),
            default_timeouts(),
        );
        let connect_observation = connect_probe
            .probe(&target(refused_port, "service.test"))
            .await;
        assert_eq!(
            connect_observation.reachability,
            ReachabilityStatus::Unknown
        );
        assert_eq!(
            connect_observation.error_code,
            Some(CertificateProbeErrorCode::ConnectRefused)
        );

        let (address, server) = start_plaintext_server().await;
        let tls_probe = test_probe(verifier, Arc::new(TokioAddressResolver), default_timeouts());
        let tls_observation = tls_probe
            .probe(&target(address.port(), "service.test"))
            .await;
        let _ = server.await;
        assert_eq!(tls_observation.reachability, ReachabilityStatus::Reachable);
        assert_eq!(tls_observation.trust, TrustStatus::Unknown);
        assert_eq!(
            tls_observation.error_code,
            Some(CertificateProbeErrorCode::TlsHandshakeFailed)
        );

        let (address, stalled_server) = start_stalled_server().await;
        let timeout_probe = test_probe(
            Arc::clone(&tls_probe.trust_verifier),
            Arc::new(TokioAddressResolver),
            ProbeTimeouts {
                dns: Duration::from_millis(100),
                connect: Duration::from_millis(100),
                target: Duration::from_millis(150),
            },
        );
        let timeout_observation = timeout_probe
            .probe(&target(address.port(), "service.test"))
            .await;
        stalled_server.abort();
        let _ = stalled_server.await;
        assert_eq!(
            timeout_observation.reachability,
            ReachabilityStatus::Reachable
        );
        assert_eq!(timeout_observation.trust, TrustStatus::Unknown);
        assert_eq!(
            timeout_observation.error_code,
            Some(CertificateProbeErrorCode::TlsTimeout)
        );
    }

    #[tokio::test]
    async fn probe_bounds_dns_timeout_and_batch_inputs() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, false);
        let verifier = verifier_for_root(issued.root, crypto_provider);
        let probe = test_probe(
            verifier,
            Arc::new(TestResolver {
                behavior: ResolverBehavior::Pending,
            }),
            ProbeTimeouts {
                dns: Duration::from_millis(20),
                connect: Duration::from_millis(20),
                target: Duration::from_millis(50),
            },
        );
        let observation = probe.probe(&target(443, "service.test")).await;
        assert_eq!(
            observation.error_code,
            Some(CertificateProbeErrorCode::DnsTimeout)
        );

        assert_eq!(
            probe.probe_all(&[], 1).await,
            Err(CertificateBatchError::InvalidTargetCount)
        );
        assert_eq!(
            probe.probe_all(&[target(443, "service.test")], 0).await,
            Err(CertificateBatchError::InvalidConcurrency)
        );
        assert_eq!(
            probe
                .probe_all(&[target(443, "service.test")], MAX_CONCURRENCY + 1)
                .await,
            Err(CertificateBatchError::InvalidConcurrency)
        );
    }

    #[tokio::test]
    async fn probe_all_preserves_target_order() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, false);
        let verifier = verifier_for_root(issued.root, crypto_provider);
        let probe = test_probe(
            verifier,
            Arc::new(TestResolver {
                behavior: ResolverBehavior::Addresses(Vec::new()),
            }),
            default_timeouts(),
        );
        let mut targets = vec![target(443, "service.test"); 3];
        for (index, target) in targets.iter_mut().enumerate() {
            target.id = format!("target-{index}");
        }

        let observations = probe.probe_all(&targets, 2).await.expect("batch probe");
        let ids: Vec<_> = observations
            .iter()
            .map(|observation| observation.target_id.as_str())
            .collect();
        assert_eq!(ids, ["target-0", "target-1", "target-2"]);
        assert!(observations.iter().all(
            |observation| observation.error_code == Some(CertificateProbeErrorCode::DnsFailed)
        ));
    }

    #[tokio::test]
    async fn probe_all_bounds_concurrency_for_one_eight_and_thirty_two_targets() {
        for target_count in [1, 8, MAX_TARGETS] {
            let crypto_provider = provider();
            let issued = issue_certificate("service.test", TestValidity::Current, false);
            let verifier = verifier_for_root(issued.root, crypto_provider);
            let active = Arc::new(AtomicUsize::new(0));
            let maximum = Arc::new(AtomicUsize::new(0));
            let resolver = Arc::new(CountingResolver {
                active: Arc::clone(&active),
                maximum: Arc::clone(&maximum),
                started: Arc::new(Notify::new()),
                delay: Duration::from_millis(10),
            });
            let probe = test_probe(verifier, resolver, default_timeouts());
            let targets = vec![target(443, "service.test"); target_count];
            let concurrency = target_count.min(MAX_CONCURRENCY);

            let observations = probe
                .probe_all(&targets, concurrency)
                .await
                .expect("bounded batch");

            assert_eq!(observations.len(), target_count);
            assert_eq!(maximum.load(Ordering::SeqCst), concurrency);
            assert_eq!(active.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn cancelling_batch_drops_in_flight_resolution_futures() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, false);
        let verifier = verifier_for_root(issued.root, crypto_provider);
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let resolver = Arc::new(CountingResolver {
            active: Arc::clone(&active),
            maximum,
            started: Arc::clone(&started),
            delay: Duration::from_secs(30),
        });
        let probe = test_probe(
            verifier,
            resolver,
            ProbeTimeouts {
                dns: Duration::from_secs(30),
                connect: Duration::from_secs(1),
                target: Duration::from_secs(30),
            },
        );
        let targets = vec![target(443, "service.test"); MAX_TARGETS];
        let task = tokio::spawn(async move { probe.probe_all(&targets, MAX_CONCURRENCY).await });

        started.notified().await;
        task.abort();
        assert!(task.await.expect_err("cancelled batch").is_cancelled());
        tokio::task::yield_now().await;

        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn certificate_evaluation_rejects_malformed_and_oversized_chains() {
        let crypto_provider = provider();
        let issued = issue_certificate("service.test", TestValidity::Current, false);
        let verifier = verifier_for_root(issued.root, Arc::clone(&crypto_provider));
        let target = target(443, "service.test");
        let server_name = ServerName::try_from("service.test".to_owned()).expect("server name");
        let malformed = vec![CertificateDer::from(vec![0x01, 0x02, 0x03])];
        assert_eq!(
            evaluate_certificates(
                &target,
                Utc::now().timestamp(),
                server_name,
                &malformed,
                verifier.as_ref()
            ),
            Err(CertificateProbeErrorCode::CertificateParseFailed)
        );

        let observer = ObservationOnlyVerifier {
            supported: crypto_provider.signature_verification_algorithms,
        };
        let leaf = CertificateDer::from(vec![0_u8; 1]);
        let intermediates = vec![CertificateDer::from(vec![0_u8; 1]); MAX_CHAIN_CERTIFICATES];
        assert!(
            observer
                .verify_server_cert(
                    &leaf,
                    &intermediates,
                    &ServerName::try_from("service.test").expect("server name"),
                    &[],
                    UnixTime::now()
                )
                .is_err()
        );

        let oversized = CertificateDer::from(vec![0_u8; MAX_CHAIN_BYTES + 1]);
        assert!(
            observer
                .verify_server_cert(
                    &oversized,
                    &[],
                    &ServerName::try_from("service.test").expect("server name"),
                    &[],
                    UnixTime::now()
                )
                .is_err()
        );
        assert_eq!(
            evaluate_certificates(
                &target,
                Utc::now().timestamp(),
                ServerName::try_from("service.test".to_owned()).expect("server name"),
                &[oversized],
                verifier.as_ref()
            ),
            Err(CertificateProbeErrorCode::CertificateParseFailed)
        );
    }
}
