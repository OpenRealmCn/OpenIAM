ALTER TABLE users ADD COLUMN phone VARCHAR(32) NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS user_totp (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    secret VARCHAR(128) NOT NULL DEFAULT '',
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    verified_at DATETIME NULL,
    recovery_codes_json TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_user_totp_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    refresh_token_hash VARCHAR(128) NOT NULL DEFAULT '',
    device_name VARCHAR(128) NOT NULL DEFAULT '',
    device_fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    user_agent VARCHAR(512) NOT NULL DEFAULT '',
    ip_address VARCHAR(64) NOT NULL DEFAULT '',
    location VARCHAR(128) NOT NULL DEFAULT '',
    last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_user_sessions_sid (session_id),
    KEY idx_user_sessions_user_id (user_id),
    KEY idx_user_sessions_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    category VARCHAR(32) NOT NULL DEFAULT 'system_message',
    level VARCHAR(16) NOT NULL DEFAULT 'info',
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    metadata JSON NULL,
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    read_at DATETIME NULL,
    created_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_notifications_user_id (user_id),
    KEY idx_notifications_category (category),
    KEY idx_notifications_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notification_templates (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    channel VARCHAR(32) NOT NULL DEFAULT 'email',
    subject VARCHAR(255) NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    variables JSON NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    updated_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_notification_templates_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    template_code VARCHAR(64) NOT NULL DEFAULT '',
    channel VARCHAR(32) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    subject VARCHAR(255) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'sent',
    provider_name VARCHAR(64) NOT NULL DEFAULT '',
    cost_cents BIGINT NOT NULL DEFAULT 0,
    error_message VARCHAR(512) NOT NULL DEFAULT '',
    bounce_reason VARCHAR(512) NOT NULL DEFAULT '',
    bounced_at DATETIME NULL,
    metadata JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_notif_deliv_tpl (template_code),
    KEY idx_notif_deliv_channel (channel),
    KEY idx_notif_deliv_user_id (user_id),
    KEY idx_notif_deliv_status (status),
    KEY idx_notif_deliv_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS risk_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    username VARCHAR(64) NOT NULL DEFAULT '',
    ip_address VARCHAR(64) NOT NULL DEFAULT '',
    location VARCHAR(128) NOT NULL DEFAULT '',
    device_fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    user_agent VARCHAR(512) NOT NULL DEFAULT '',
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'low',
    reasons JSON NOT NULL,
    action_taken VARCHAR(32) NOT NULL DEFAULT 'allow',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_risk_events_user_id (user_id),
    KEY idx_risk_events_level (risk_level),
    KEY idx_risk_events_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS temp_role_grants (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    domain_code VARCHAR(64) NOT NULL,
    role_code VARCHAR(64) NOT NULL,
    reason VARCHAR(512) NOT NULL DEFAULT '',
    granted_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
    starts_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    activated_at DATETIME NULL,
    revoked_at DATETIME NULL,
    revoked_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY idx_temp_grants_user_id (user_id),
    KEY idx_temp_grants_domain (domain_code),
    KEY idx_temp_grants_expires_at (expires_at),
    KEY idx_temp_grants_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS plugin_instances (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    slot VARCHAR(32) NOT NULL,
    plugin_type VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    config JSON NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    priority INT NOT NULL DEFAULT 100,
    health_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    last_checked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_plugin_instances_name (name),
    KEY idx_plugin_instances_slot (slot)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
