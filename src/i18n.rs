pub use axum::http::HeaderMap;
use std::env;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    EN,
    RU,
}

impl Lang {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        if let Some(accept_lang) = headers.get("accept-language")
            && let Ok(s) = accept_lang.to_str()
        {
            let s_lower = s.to_lowercase();
            if s_lower.contains("ru") {
                return Lang::RU;
            } else if s_lower.contains("en") {
                return Lang::EN;
            }
        }

        // Fallback to env or EN
        let l = env::var("AGENT_LANG").unwrap_or_else(|_| "en".to_string());
        if l.to_lowercase() == "ru" {
            Lang::RU
        } else {
            Lang::EN
        }
    }
}

pub fn t(key: &str, lang: &Lang) -> String {
    match lang {
        Lang::RU => match key {
            "alert.critical_cpu" => "Критическая нагрузка CPU: {val}%".to_string(),
            "alert.low_disk" => "Мало места на диске: {val}% занято".to_string(),
            "alert.test" => "Это тестовое уведомление от агента Mini-Ops!".to_string(),
            "security.detected" => "Обнаружена проблема безопасности!".to_string(),
            "security.resolved" => "✅ Проблема безопасности решена".to_string(),
            "security.check" => "Проверка".to_string(),
            "security.message" => "Описание".to_string(),
            "security.ssh_source_ip.title" => "SSH-вход с недоверенного IP-источника".to_string(),
            "security.ssh_source_ip.message" => "SSH-вход не совпадает с baseline доверенных IP".to_string(),
            "notification.delivery_degraded.title" => "Доставка уведомлений работает в degraded mode".to_string(),
            "notification.delivery_degraded.message" => "Очередь уведомлений достигла лимита; новые доставки временно ограничены".to_string(),
            "certificate.expiry.title" => "Срок действия TLS-сертификата".to_string(),
            "certificate.expiry.message" => "Сертификат требует внимания".to_string(),
            "certificate.expiry.remediation" => "Обновите сертификат и убедитесь, что сервис отдаёт новую цепочку".to_string(),
            "certificate.hostname.title" => "TLS hostname".to_string(),
            "certificate.hostname.message" => "Сертификат не соответствует ожидаемому имени".to_string(),
            "certificate.hostname.remediation" => "Исправьте SNI/hostname или установите сертификат с ожидаемым SAN".to_string(),
            "certificate.trust.title" => "Доверие к TLS-сертификату".to_string(),
            "certificate.trust.message" => "Цепочка сертификата не прошла проверку системного trust store".to_string(),
            "certificate.trust.remediation" => "Установите полную доверенную цепочку и повторите проверку".to_string(),
            "certificate.coverage.title" => "Проверка TLS-сертификата неполна".to_string(),
            "certificate.coverage.message" => "Одна или несколько характеристик сертификата остались неизвестными".to_string(),
            "certificate.coverage.remediation" => "Проверьте DNS, TCP/TLS-доступность и конфигурацию целевого сервиса".to_string(),
            "certificate.state.warning" => "приближается срок окончания".to_string(),
            "certificate.state.critical" => "критически малый остаток срока".to_string(),
            "certificate.state.expired" => "срок действия истёк".to_string(),
            "certificate.state.not_yet_valid" => "сертификат ещё не действует".to_string(),
            "certificate.state.mismatch" => "имя не совпадает".to_string(),
            "certificate.state.invalid" => "цепочка недоверенная".to_string(),

            "audit.collection.name" => "Сбор данных аудита".to_string(),
            "audit.collection.error" => "Сбор данных аудита превысил общий лимит времени".to_string(),
            "audit.collection.degraded" => "Снимок аудита неполный или недоступен; одна или несколько проверок имеют неизвестное состояние".to_string(),
            "audit.collection.remediation" => "Проверьте доступность системных утилит и повторите аудит".to_string(),

            "audit.ssh_root.name" => "Доступ root через SSH".to_string(),
            "audit.ssh_root.fail" => "Root-доступ разрешен по паролю/ключам (небезопасно)".to_string(),
            "audit.ssh_root.pass" => "Доступ root отключён в проверенном SSH context".to_string(),
            "audit.ssh_root.warn_restricted" => "Root-доступ ограничен, но не полностью отключен".to_string(),
            "audit.ssh_root.warn_unknown" => "Не удалось определить effective-значение PermitRootLogin".to_string(),
            "audit.ssh_root.remediation" => "Установите PermitRootLogin no и перезапустите sshd".to_string(),
            "audit.ssh_config.warn" => "Не удалось подтвердить effective-конфигурацию sshd".to_string(),

            "audit.ufw.name" => "Файрвол (UFW)".to_string(),
            "audit.ufw.pass" => "UFW активен".to_string(),
            "audit.ufw.fail" => "UFW отключен".to_string(),
            "audit.ufw.warn" => "UFW не найден или недоступен".to_string(),
            "audit.ufw.error" => "UFW найден, но команда не выполнена (возможно, недостаточно прав)".to_string(),
            "audit.ufw.remediation" => "Включите firewall и разрешите только необходимые порты".to_string(),

            "audit.docker_sock.name" => "Права на Docker Socket".to_string(),
            "audit.docker_sock.fail" => "Docker socket должен принадлежать root и не иметь world-write прав".to_string(),
            "audit.docker_sock.pass" => "Final Unix socket принадлежит root и не имеет world-write прав".to_string(),
            "audit.docker_sock.warn" => "Не удалось доказать безопасный final Unix socket /var/run/docker.sock".to_string(),
            "audit.docker_sock.remediation" => "Используйте root-owned final Unix socket без world-write прав и ограничьте доступ группы docker".to_string(),
            "audit.docker_api.name" => "Docker TCP API".to_string(),
            "audit.docker_api.pass" => "Docker TCP API не найден на стандартных портах".to_string(),
            "audit.docker_api.fail" => "Docker API слушает TCP порт".to_string(),
            "audit.docker_api.remediation" => "Отключите Docker TCP API или защитите его TLS, firewall и строгой авторизацией".to_string(),
            "audit.docker_control.name" => "Доступ Mini-Ops к управлению Docker".to_string(),
            "audit.docker_control.pass" => "Локальный Docker runtime на default socket не обнаружен".to_string(),
            "audit.docker_control.unverified" => "Docker client настроен, но доступ Mini-Ops к локальному daemon API подтвердить не удалось".to_string(),
            "audit.docker_control.recommendation" => "Подтверждён доступ Mini-Ops к Docker daemon API через локальный socket; доступ к обычному daemon следует считать root-equivalent, если daemon не является независимо ограниченным или rootless".to_string(),
            "audit.docker_control.remediation" => "Проверьте trust boundary Docker daemon, предоставляйте доступ только доверенному экземпляру Mini-Ops, ограничьте доступ к панели и отзовите доступ к socket/API, если управление контейнерами не требуется".to_string(),
            "audit.docker_containers.name" => "Hardening Docker контейнеров".to_string(),
            "audit.docker_containers.pass" => "Проверенные Docker hardening facts не содержат известных рисков".to_string(),
            "audit.docker_containers.fail" => "Найдены рискованные настройки контейнеров".to_string(),
            "audit.docker_containers.error" => "Не удалось проверить настройки контейнеров".to_string(),
            "audit.docker_containers.timeout" => "Проверка Docker контейнеров превысила лимит времени".to_string(),
            "audit.docker_containers.no_runtime" => "Docker runtime не обнаружен".to_string(),
            "audit.docker_containers.unavailable" => "Docker socket есть, но inspection недоступен".to_string(),
            "audit.docker_containers.remediation" => "Уберите privileged/host namespaces, explicit capabilities/devices и чувствительные mounts; включите default seccomp, MAC, system paths и no-new-privileges".to_string(),

            "audit.disk_enc.name" => "Шифрование диска".to_string(),
            "audit.disk_enc.pass" => "Подтверждена зашифрованная цепочка устройства корневого раздела".to_string(),
            "audit.disk_enc.warn" => "Не удалось подтвердить шифрование цепочки устройства корневого раздела".to_string(),
            "audit.disk_enc.error" => "Не удалось определить цепочку устройства корневого раздела через lsblk".to_string(),
            "audit.disk_enc.remediation" => "Для новых серверов используйте LUKS или шифрование диска у провайдера".to_string(),

            "audit.fail2ban.name" => "Fail2Ban".to_string(),
            "audit.fail2ban.pass" => "Сервис активен".to_string(),
            "audit.fail2ban.warn" => "Сервис не запущен".to_string(),
            "audit.fail2ban.missing" => "Fail2Ban не установлен".to_string(),
            "audit.fail2ban.remediation" => "Установите и включите Fail2Ban или аналогичную защиту от brute force".to_string(),

            "audit.ssh_passwd.name" => "SSH Password Auth".to_string(),
            "audit.ssh_passwd.pass" => "В проверенном SSH context отключены password и keyboard-interactive authentication".to_string(),
            "audit.ssh_passwd.fail" => "В проверенном SSH context включён password или keyboard-interactive authentication".to_string(),
            "audit.ssh_passwd.remediation" => "Установите PasswordAuthentication no и KbdInteractiveAuthentication no, затем используйте SSH-ключи".to_string(),

            "audit.ports.name" => "Открытые порты".to_string(),
            "audit.ports.pass" => "Найдены только ожидаемые listening ports".to_string(),
            "audit.ports.warn" => "Найдены неожиданные listening ports".to_string(),
            "audit.ports.error" => "Ошибка сканирования портов".to_string(),
            "audit.ports.config_error" => "Список разрешённых портов содержит некорректные значения".to_string(),
            "audit.ports.remediation" => "Закройте неожиданные listening ports, привяжите приватные сервисы к loopback, защитите их firewall-правилами или добавьте ожидаемые public/loopback порты в SECURITY_ALLOWED_PUBLIC_PORTS и SECURITY_ALLOWED_LOOPBACK_PORTS".to_string(),
            _ => key.to_string(),
        },
        Lang::EN => match key {
            "alert.critical_cpu" => "Critical CPU usage: {val}%".to_string(),
            "alert.low_disk" => "Low disk space: {val}% used".to_string(),
            "alert.test" => "This is a test notification from Mini-Ops agent!".to_string(),
            "security.detected" => "Security Issue Detected!".to_string(),
            "security.resolved" => "✅ Security Issue Resolved".to_string(),
            "security.check" => "Check".to_string(),
            "security.message" => "Message".to_string(),
            "security.ssh_source_ip.title" => "SSH login from untrusted source IP".to_string(),
            "security.ssh_source_ip.message" => "SSH login does not match the trusted IP baseline".to_string(),
            "notification.delivery_degraded.title" => "Notification delivery is degraded".to_string(),
            "notification.delivery_degraded.message" => "The notification queue reached its capacity; new deliveries are temporarily backpressured".to_string(),
            "certificate.expiry.title" => "TLS certificate expiry".to_string(),
            "certificate.expiry.message" => "The certificate requires attention".to_string(),
            "certificate.expiry.remediation" => "Renew the certificate and verify that the service presents the new chain".to_string(),
            "certificate.hostname.title" => "TLS hostname".to_string(),
            "certificate.hostname.message" => "The certificate does not match the expected name".to_string(),
            "certificate.hostname.remediation" => "Correct the SNI/hostname or install a certificate with the expected SAN".to_string(),
            "certificate.trust.title" => "TLS certificate trust".to_string(),
            "certificate.trust.message" => "The certificate chain did not validate against the system trust store".to_string(),
            "certificate.trust.remediation" => "Install a complete trusted chain and run the check again".to_string(),
            "certificate.coverage.title" => "TLS certificate check is incomplete".to_string(),
            "certificate.coverage.message" => "One or more certificate dimensions remain unknown".to_string(),
            "certificate.coverage.remediation" => "Verify DNS, TCP/TLS reachability, and the target service configuration".to_string(),
            "certificate.state.warning" => "expiry is approaching".to_string(),
            "certificate.state.critical" => "very little validity remains".to_string(),
            "certificate.state.expired" => "the certificate has expired".to_string(),
            "certificate.state.not_yet_valid" => "the certificate is not valid yet".to_string(),
            "certificate.state.mismatch" => "the name does not match".to_string(),
            "certificate.state.invalid" => "the chain is not trusted".to_string(),

            "audit.collection.name" => "Security Audit Collection".to_string(),
            "audit.collection.error" => "Security audit collection exceeded its overall deadline".to_string(),
            "audit.collection.degraded" => "The security audit snapshot is incomplete or unavailable; one or more checks have unknown state".to_string(),
            "audit.collection.remediation" => "Verify that required system tools respond and run the audit again".to_string(),

            "audit.ssh_root.name" => "SSH Root Login".to_string(),
            "audit.ssh_root.fail" => "Root login is permitted via SSH via password/keys".to_string(),
            "audit.ssh_root.pass" => "Root login is disabled in the evaluated SSH context".to_string(),
            "audit.ssh_root.warn_restricted" => "Root login is restricted but not fully disabled".to_string(),
            "audit.ssh_root.warn_unknown" => "Could not determine effective PermitRootLogin value".to_string(),
            "audit.ssh_root.remediation" => "Set PermitRootLogin no and restart sshd".to_string(),
            "audit.ssh_config.warn" => "Could not establish the effective sshd configuration".to_string(),

            "audit.ufw.name" => "Firewall (UFW)".to_string(),
            "audit.ufw.pass" => "UFW is active".to_string(),
            "audit.ufw.fail" => "UFW is inactive".to_string(),
            "audit.ufw.warn" => "UFW command not found or not accessible".to_string(),
            "audit.ufw.error" => "UFW found but command failed (possibly insufficient permissions)".to_string(),
            "audit.ufw.remediation" => "Enable a firewall and allow only required ports".to_string(),

            "audit.docker_sock.name" => "Docker Socket Permissions".to_string(),
            "audit.docker_sock.fail" => "Docker socket must be root-owned and not world-writable".to_string(),
            "audit.docker_sock.pass" => "The final Unix socket is root-owned and not world-writable".to_string(),
            "audit.docker_sock.warn" => "Could not prove a safe final Unix socket at /var/run/docker.sock".to_string(),
            "audit.docker_sock.remediation" => "Use a root-owned final Unix socket without world-write permissions and restrict docker group access".to_string(),
            "audit.docker_api.name" => "Docker TCP API".to_string(),
            "audit.docker_api.pass" => "Docker TCP API was not found on default ports".to_string(),
            "audit.docker_api.fail" => "Docker API is listening on a TCP port".to_string(),
            "audit.docker_api.remediation" => "Disable Docker TCP API or protect it with TLS, firewall rules, and strict authorization".to_string(),
            "audit.docker_control.name" => "Mini-Ops Docker Control Access".to_string(),
            "audit.docker_control.pass" => "No local Docker runtime was detected at the default socket".to_string(),
            "audit.docker_control.unverified" => "The Docker client is configured, but Mini-Ops access to the local daemon API could not be confirmed".to_string(),
            "audit.docker_control.recommendation" => "Mini-Ops access to the Docker daemon API through the local socket is confirmed; treat access to a conventional daemon as root-equivalent unless the daemon is independently constrained or rootless".to_string(),
            "audit.docker_control.remediation" => "Verify the Docker daemon trust boundary, grant access only to a trusted Mini-Ops instance, restrict dashboard access, and revoke socket/API access when container control is not required".to_string(),
            "audit.docker_containers.name" => "Docker Container Hardening".to_string(),
            "audit.docker_containers.pass" => "No known risks found in the checked Docker hardening facts".to_string(),
            "audit.docker_containers.fail" => "Risky container settings found".to_string(),
            "audit.docker_containers.error" => "Could not inspect container settings".to_string(),
            "audit.docker_containers.timeout" => "Docker container inspection timed out".to_string(),
            "audit.docker_containers.no_runtime" => "Docker runtime was not detected".to_string(),
            "audit.docker_containers.unavailable" => "Docker socket exists, but inspection is unavailable".to_string(),
            "audit.docker_containers.remediation" => "Remove privileged/host namespaces, explicit capabilities/devices, and sensitive mounts; enable default seccomp, MAC, system paths, and no-new-privileges".to_string(),

            "audit.disk_enc.name" => "Disk Encryption".to_string(),
            "audit.disk_enc.pass" => "The root filesystem backing chain is proven encrypted".to_string(),
            "audit.disk_enc.warn" => "Encryption could not be proven for the root filesystem backing chain".to_string(),
            "audit.disk_enc.error" => "Could not determine the root filesystem backing chain with lsblk".to_string(),
            "audit.disk_enc.remediation" => "Use LUKS or provider-managed disk encryption for new servers".to_string(),

            "audit.fail2ban.name" => "Fail2Ban".to_string(),
            "audit.fail2ban.pass" => "Service is active".to_string(),
            "audit.fail2ban.warn" => "Service is not running".to_string(),
            "audit.fail2ban.missing" => "Fail2Ban is not installed".to_string(),
            "audit.fail2ban.remediation" => "Install and enable Fail2Ban or equivalent brute-force protection".to_string(),

            "audit.ssh_passwd.name" => "SSH Password Auth".to_string(),
            "audit.ssh_passwd.pass" => "Password and keyboard-interactive authentication are disabled in the evaluated SSH context".to_string(),
            "audit.ssh_passwd.fail" => "Password or keyboard-interactive authentication is enabled in the evaluated SSH context".to_string(),
            "audit.ssh_passwd.remediation" => "Set PasswordAuthentication no and KbdInteractiveAuthentication no, then use SSH keys".to_string(),

            "audit.ports.name" => "Listening Ports".to_string(),
            "audit.ports.pass" => "Only expected listening ports found".to_string(),
            "audit.ports.warn" => "Unexpected listening ports found".to_string(),
            "audit.ports.error" => "Error scanning ports".to_string(),
            "audit.ports.config_error" => "The allowed-port configuration contains invalid values".to_string(),
            "audit.ports.remediation" => "Close unexpected listening ports, bind private services to loopback, protect them with firewall rules, or add expected public/loopback ports to SECURITY_ALLOWED_PUBLIC_PORTS and SECURITY_ALLOWED_LOOPBACK_PORTS".to_string(),
            _ => key.to_string(),
        }
    }
}

pub fn t_val(key: &str, lang: &Lang, val: &str) -> String {
    t(key, lang).replace("{val}", val)
}
