ALTER TABLE users DROP INDEX idx_users_phone;
ALTER TABLE users DROP INDEX idx_users_email;
ALTER TABLE users ADD UNIQUE KEY uk_users_email (email);
