DROP TABLE IF EXISTS plugin_instances;
DROP TABLE IF EXISTS temp_role_grants;
DROP TABLE IF EXISTS risk_events;
DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_templates;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_totp;
ALTER TABLE users DROP COLUMN phone;
