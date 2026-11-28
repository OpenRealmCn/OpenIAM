-- 邮箱与手机号可用于验证码登录、二步验证与密码重置，必须全局唯一（空值除外，大小写不敏感）。
-- 注意：若现有数据存在重复邮箱/手机号，本迁移会失败，需先人工合并或清理重复账号后再升级：
--   SELECT LOWER(email), COUNT(*) FROM users WHERE email <> '' GROUP BY LOWER(email) HAVING COUNT(*) > 1;
--   SELECT phone, COUNT(*) FROM users WHERE phone <> '' GROUP BY phone HAVING COUNT(*) > 1;
ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0 AFTER email;
ALTER TABLE users ADD COLUMN email_norm VARCHAR(128) GENERATED ALWAYS AS (NULLIF(LOWER(email), '')) STORED;
ALTER TABLE users ADD COLUMN phone_norm VARCHAR(32) GENERATED ALWAYS AS (NULLIF(phone, '')) STORED;
ALTER TABLE users ADD UNIQUE KEY uk_users_email_norm (email_norm);
ALTER TABLE users ADD UNIQUE KEY uk_users_phone_norm (phone_norm);

CREATE TABLE IF NOT EXISTS notification_reads (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    notification_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    read_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_notification_reads (notification_id, user_id),
    KEY idx_notification_reads_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
