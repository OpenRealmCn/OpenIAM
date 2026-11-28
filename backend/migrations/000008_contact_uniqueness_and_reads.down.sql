DROP TABLE IF EXISTS notification_reads;
ALTER TABLE users DROP INDEX uk_users_phone_norm;
ALTER TABLE users DROP INDEX uk_users_email_norm;
ALTER TABLE users DROP COLUMN phone_norm;
ALTER TABLE users DROP COLUMN email_norm;
ALTER TABLE users DROP COLUMN email_verified;
