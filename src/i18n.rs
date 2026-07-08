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

            "audit.ssh_root.name" => "Доступ root через SSH".to_string(),
            "audit.ssh_root.fail" => "Root-доступ разрешен по паролю/ключам (небезопасно)".to_string(),
            "audit.ssh_root.pass" => "Доступ для root ограничен или отключен".to_string(),
            "audit.ssh_root.warn_restricted" => "Root-доступ ограничен, но не полностью отключен".to_string(),
            "audit.ssh_root.warn_unknown" => "Не удалось определить effective-значение PermitRootLogin".to_string(),
            "audit.ssh_root.remediation" => "Установите PermitRootLogin no и перезапустите sshd".to_string(),
            "audit.ssh_config.warn" => "Не удалось прочитать конфиг sshd".to_string(),

            "audit.ufw.name" => "Файрвол (UFW)".to_string(),
            "audit.ufw.pass" => "UFW активен".to_string(),
            "audit.ufw.fail" => "UFW отключен".to_string(),
            "audit.ufw.warn" => "UFW не найден или недоступен".to_string(),
            "audit.ufw.error" => "UFW найден, но команда не выполнена (возможно, недостаточно прав)".to_string(),
            "audit.ufw.remediation" => "Включите firewall и разрешите только необходимые порты".to_string(),

            "audit.docker_sock.name" => "Права на Docker Socket".to_string(),
            "audit.docker_sock.fail" => "Socket доступен всем на запись (опасно!)".to_string(),
            "audit.docker_sock.pass" => "Права доступа выглядят безопасно".to_string(),
            "audit.docker_sock.warn" => "Не удалось проверить /var/run/docker.sock".to_string(),
            "audit.docker_sock.remediation" => "Уберите world-write права с Docker socket и ограничьте группу docker".to_string(),
            "audit.docker_api.name" => "Docker TCP API".to_string(),
            "audit.docker_api.pass" => "Docker TCP API не найден на стандартных портах".to_string(),
            "audit.docker_api.fail" => "Docker API слушает TCP порт".to_string(),
            "audit.docker_api.remediation" => "Отключите Docker TCP API или защитите его TLS, firewall и строгой авторизацией".to_string(),
            "audit.docker_containers.name" => "Hardening Docker контейнеров".to_string(),
            "audit.docker_containers.pass" => "Опасных настроек контейнеров не найдено".to_string(),
            "audit.docker_containers.fail" => "Найдены рискованные настройки контейнеров".to_string(),
            "audit.docker_containers.error" => "Не удалось проверить настройки контейнеров".to_string(),
            "audit.docker_containers.timeout" => "Проверка Docker контейнеров превысила лимит времени".to_string(),
            "audit.docker_containers.no_runtime" => "Docker runtime не обнаружен".to_string(),
            "audit.docker_containers.unavailable" => "Docker socket есть, но inspection недоступен".to_string(),
            "audit.docker_containers.remediation" => "Уберите privileged, host namespaces, опасные capabilities и чувствительные host mounts".to_string(),

            "audit.disk_enc.name" => "Шифрование диска".to_string(),
            "audit.disk_enc.pass" => "Найдены зашифрованные разделы".to_string(),
            "audit.disk_enc.warn" => "Зашифрованные разделы LUKS не найдены".to_string(),
            "audit.disk_enc.error" => "Не удалось запустить lsblk".to_string(),
            "audit.disk_enc.remediation" => "Для новых серверов используйте LUKS или шифрование диска у провайдера".to_string(),

            "audit.fail2ban.name" => "Fail2Ban".to_string(),
            "audit.fail2ban.pass" => "Сервис активен".to_string(),
            "audit.fail2ban.warn" => "Сервис не запущен".to_string(),
            "audit.fail2ban.missing" => "Fail2Ban не установлен".to_string(),
            "audit.fail2ban.remediation" => "Установите и включите Fail2Ban или аналогичную защиту от brute force".to_string(),

            "audit.ssh_passwd.name" => "SSH Password Auth".to_string(),
            "audit.ssh_passwd.pass" => "Вход по паролю отключен".to_string(),
            "audit.ssh_passwd.fail" => "Вход по паролю включен (небезопасно)".to_string(),
            "audit.ssh_passwd.remediation" => "Установите PasswordAuthentication no и используйте SSH-ключи".to_string(),

            "audit.ports.name" => "Открытые порты".to_string(),
            "audit.ports.pass" => "Найдены только ожидаемые listening ports".to_string(),
            "audit.ports.warn" => "Найдены неожиданные listening ports".to_string(),
            "audit.ports.error" => "Ошибка сканирования портов".to_string(),
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

            "audit.ssh_root.name" => "SSH Root Login".to_string(),
            "audit.ssh_root.fail" => "Root login is permitted via SSH via password/keys".to_string(),
            "audit.ssh_root.pass" => "Root login appears disabled or restricted".to_string(),
            "audit.ssh_root.warn_restricted" => "Root login is restricted but not fully disabled".to_string(),
            "audit.ssh_root.warn_unknown" => "Could not determine effective PermitRootLogin value".to_string(),
            "audit.ssh_root.remediation" => "Set PermitRootLogin no and restart sshd".to_string(),
            "audit.ssh_config.warn" => "Could not read /etc/ssh/sshd_config".to_string(),

            "audit.ufw.name" => "Firewall (UFW)".to_string(),
            "audit.ufw.pass" => "UFW is active".to_string(),
            "audit.ufw.fail" => "UFW is inactive".to_string(),
            "audit.ufw.warn" => "UFW command not found or not accessible".to_string(),
            "audit.ufw.error" => "UFW found but command failed (possibly insufficient permissions)".to_string(),
            "audit.ufw.remediation" => "Enable a firewall and allow only required ports".to_string(),

            "audit.docker_sock.name" => "Docker Socket Permissions".to_string(),
            "audit.docker_sock.fail" => "Docker socket is world-writable (dangerous!)".to_string(),
            "audit.docker_sock.pass" => "Permissions look safe".to_string(),
            "audit.docker_sock.warn" => "Could not verify /var/run/docker.sock".to_string(),
            "audit.docker_sock.remediation" => "Remove world-write permissions from the Docker socket and restrict docker group access".to_string(),
            "audit.docker_api.name" => "Docker TCP API".to_string(),
            "audit.docker_api.pass" => "Docker TCP API was not found on default ports".to_string(),
            "audit.docker_api.fail" => "Docker API is listening on a TCP port".to_string(),
            "audit.docker_api.remediation" => "Disable Docker TCP API or protect it with TLS, firewall rules, and strict authorization".to_string(),
            "audit.docker_containers.name" => "Docker Container Hardening".to_string(),
            "audit.docker_containers.pass" => "No dangerous container settings found".to_string(),
            "audit.docker_containers.fail" => "Risky container settings found".to_string(),
            "audit.docker_containers.error" => "Could not inspect container settings".to_string(),
            "audit.docker_containers.timeout" => "Docker container inspection timed out".to_string(),
            "audit.docker_containers.no_runtime" => "Docker runtime was not detected".to_string(),
            "audit.docker_containers.unavailable" => "Docker socket exists, but inspection is unavailable".to_string(),
            "audit.docker_containers.remediation" => "Remove privileged mode, host namespaces, dangerous capabilities, and sensitive host mounts".to_string(),

            "audit.disk_enc.name" => "Disk Encryption".to_string(),
            "audit.disk_enc.pass" => "Found encrypted partitions".to_string(),
            "audit.disk_enc.warn" => "No LUKS encrypted partitions found".to_string(),
            "audit.disk_enc.error" => "Could not run lsblk".to_string(),
            "audit.disk_enc.remediation" => "Use LUKS or provider-managed disk encryption for new servers".to_string(),

            "audit.fail2ban.name" => "Fail2Ban".to_string(),
            "audit.fail2ban.pass" => "Service is active".to_string(),
            "audit.fail2ban.warn" => "Service is not running".to_string(),
            "audit.fail2ban.missing" => "Fail2Ban is not installed".to_string(),
            "audit.fail2ban.remediation" => "Install and enable Fail2Ban or equivalent brute-force protection".to_string(),

            "audit.ssh_passwd.name" => "SSH Password Auth".to_string(),
            "audit.ssh_passwd.pass" => "Password authentication is disabled".to_string(),
            "audit.ssh_passwd.fail" => "Password authentication is enabled (insecure)".to_string(),
            "audit.ssh_passwd.remediation" => "Set PasswordAuthentication no and use SSH keys".to_string(),

            "audit.ports.name" => "Listening Ports".to_string(),
            "audit.ports.pass" => "Only expected listening ports found".to_string(),
            "audit.ports.warn" => "Unexpected listening ports found".to_string(),
            "audit.ports.error" => "Error scanning ports".to_string(),
            "audit.ports.remediation" => "Close unexpected listening ports, bind private services to loopback, protect them with firewall rules, or add expected public/loopback ports to SECURITY_ALLOWED_PUBLIC_PORTS and SECURITY_ALLOWED_LOOPBACK_PORTS".to_string(),
            _ => key.to_string(),
        }
    }
}

pub fn t_val(key: &str, lang: &Lang, val: &str) -> String {
    t(key, lang).replace("{val}", val)
}
