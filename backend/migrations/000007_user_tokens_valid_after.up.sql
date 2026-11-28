-- 凭据有效起点：改密、重置密码、踢下线时写入当前毫秒时间戳，
-- 签发时间早于或等于该时刻的刷新令牌一律作废（旧刷新令牌不能再换出新令牌）。
ALTER TABLE users
    ADD COLUMN tokens_valid_after BIGINT NULL DEFAULT NULL AFTER must_change_password;
