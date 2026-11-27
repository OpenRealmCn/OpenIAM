CREATE TABLE IF NOT EXISTS oauth_clients (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(128) NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL DEFAULT '',
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512) NOT NULL DEFAULT '',
    domain_code VARCHAR(64) NOT NULL DEFAULT 'openiam',
    redirect_uris JSON NOT NULL,
    grant_types JSON NOT NULL,
    scopes JSON NOT NULL,
    require_pkce TINYINT(1) NOT NULL DEFAULT 1,
    is_confidential TINYINT(1) NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_oauth_clients_client_id (client_id),
    KEY idx_oauth_clients_domain (domain_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS oauth_providers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    plugin_type VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    client_id VARCHAR(255) NOT NULL DEFAULT '',
    client_secret VARCHAR(512) NOT NULL DEFAULT '',
    scopes VARCHAR(512) NOT NULL DEFAULT '',
    extra_config JSON NULL,
    auto_register TINYINT(1) NOT NULL DEFAULT 1,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_oauth_providers_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_identities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    provider_name VARCHAR(64) NOT NULL,
    external_user_id VARCHAR(255) NOT NULL,
    external_username VARCHAR(255) NOT NULL DEFAULT '',
    external_email VARCHAR(255) NOT NULL DEFAULT '',
    raw_profile JSON NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_user_identities_provider_ext (provider_name, external_user_id),
    KEY idx_user_identities_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    actor_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    actor_username VARCHAR(64) NOT NULL DEFAULT '',
    domain_code VARCHAR(64) NOT NULL DEFAULT 'openiam',
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL DEFAULT '',
    before_state JSON NULL,
    after_state JSON NULL,
    ip_address VARCHAR(64) NOT NULL DEFAULT '',
    user_agent VARCHAR(512) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'success',
    error_message VARCHAR(512) NOT NULL DEFAULT '',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_audit_actor (actor_id, created_at),
    KEY idx_audit_domain_action (domain_code, action, created_at),
    KEY idx_audit_resource (resource_type, resource_id),
    KEY idx_audit_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
