ALTER TABLE users DROP INDEX uk_users_email;
ALTER TABLE users MODIFY COLUMN email VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE users ADD INDEX idx_users_email (email);
ALTER TABLE users ADD INDEX idx_users_phone (phone);
