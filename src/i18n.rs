use std::env;
pub use axum::http::HeaderMap;

#[derive(Clone, Copy, Debug)]
pub enum Lang {
    EN,
    RU,
}

impl Lang {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        if let Some(accept_lang) = headers.get("accept-language") {
            if let Ok(s) = accept_lang.to_str() {
                let s_lower = s.to_lowercase();
                if s_lower.contains("ru") {
                    return Lang::RU;
                } else if s_lower.contains("en") {
                    return Lang::EN;
                }
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
            "audit.ssh_config.warn" => "Не удалось прочитать конфиг sshd".to_string(),
            
            "audit.ufw.name" => "Файрвол (UFW)".to_string(),
            "audit.ufw.pass" => "UFW активен".to_string(),
            "audit.ufw.fail" => "UFW отключен".to_string(),
            "audit.ufw.warn" => "UFW не найден или недоступен".to_string(),
            "audit.ufw.error" => "UFW найден, но команда не выполнена (возможно, недостаточно прав)".to_string(),
            
            "audit.docker_sock.name" => "Права на Docker Socket".to_string(),
            "audit.docker_sock.fail" => "Socket доступен всем на запись (опасно!)".to_string(),
            "audit.docker_sock.pass" => "Права доступа выглядят безопасно".to_string(),
            "audit.docker_sock.warn" => "Не удалось проверить /var/run/docker.sock".to_string(),
            
            "audit.disk_enc.name" => "Шифрование диска".to_string(),
            "audit.disk_enc.pass" => "Найдены зашифрованные разделы".to_string(),
            "audit.disk_enc.warn" => "Зашифрованные разделы LUKS не найдены".to_string(),
            "audit.disk_enc.error" => "Не удалось запустить lsblk".to_string(),
            
            "audit.fail2ban.name" => "Fail2Ban".to_string(),
            "audit.fail2ban.pass" => "Сервис активен".to_string(),
            "audit.fail2ban.warn" => "Сервис не запущен".to_string(),
            "audit.fail2ban.missing" => "Fail2Ban не установлен".to_string(),
            
            "audit.ssh_passwd.name" => "SSH Password Auth".to_string(),
            "audit.ssh_passwd.pass" => "Вход по паролю отключен".to_string(),
            "audit.ssh_passwd.fail" => "Вход по паролю включен (небезопасно)".to_string(),
            
            "audit.ports.name" => "Открытые порты".to_string(),
            "audit.ports.pass" => "Подозрительных портов не найдено".to_string(),
            "audit.ports.warn" => "Найдены лишние порты".to_string(),
            "audit.ports.error" => "Ошибка сканирования портов".to_string(),
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
            "audit.ssh_config.warn" => "Could not read /etc/ssh/sshd_config".to_string(),
            
            "audit.ufw.name" => "Firewall (UFW)".to_string(),
            "audit.ufw.pass" => "UFW is active".to_string(),
            "audit.ufw.fail" => "UFW is inactive".to_string(),
            "audit.ufw.warn" => "UFW command not found or not accessible".to_string(),
            "audit.ufw.error" => "UFW found but command failed (possibly insufficient permissions)".to_string(),
            
            "audit.docker_sock.name" => "Docker Socket Permissions".to_string(),
            "audit.docker_sock.fail" => "Docker socket is world-writable (dangerous!)".to_string(),
            "audit.docker_sock.pass" => "Permissions look safe".to_string(),
            "audit.docker_sock.warn" => "Could not verify /var/run/docker.sock".to_string(),
            
            "audit.disk_enc.name" => "Disk Encryption".to_string(),
            "audit.disk_enc.pass" => "Found encrypted partitions".to_string(),
            "audit.disk_enc.warn" => "No LUKS encrypted partitions found".to_string(),
            "audit.disk_enc.error" => "Could not run lsblk".to_string(),

            "audit.fail2ban.name" => "Fail2Ban".to_string(),
            "audit.fail2ban.pass" => "Service is active".to_string(),
            "audit.fail2ban.warn" => "Service is not running".to_string(),
            "audit.fail2ban.missing" => "Fail2Ban is not installed".to_string(),

            "audit.ssh_passwd.name" => "SSH Password Auth".to_string(),
            "audit.ssh_passwd.pass" => "Password authentication is disabled".to_string(),
            "audit.ssh_passwd.fail" => "Password authentication is enabled (insecure)".to_string(),

            "audit.ports.name" => "Listening Ports".to_string(),
            "audit.ports.pass" => "No suspicious ports found".to_string(),
            "audit.ports.warn" => "Unnecessary ports found".to_string(),
            "audit.ports.error" => "Error scanning ports".to_string(),
            _ => key.to_string(),
        }
    }
}

pub fn t_val(key: &str, lang: &Lang, val: &str) -> String {
    t(key, lang).replace("{val}", val)
}
