-- TOTP 重放保护：记录用户已经用掉的最大时间步，同一串动态码在有效窗口内只能使用一次。
ALTER TABLE user_totp
    ADD COLUMN last_used_step BIGINT NOT NULL DEFAULT 0 AFTER recovery_codes_json;
