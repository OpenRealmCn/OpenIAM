CREATE TABLE IF NOT EXISTS user_passkeys (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    credential_id VARCHAR(512) NOT NULL,
    name VARCHAR(128) NOT NULL DEFAULT '',
    credential_json TEXT NOT NULL,
    last_used_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_user_passkeys_cred (credential_id),
    KEY idx_user_passkeys_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
