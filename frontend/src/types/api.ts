export interface Domain {
  id: number;
  code: string;
  name: string;
  description: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: number;
  username: string;
  email: string;
  phone?: string;
  display_name: string;
  avatar_url: string;
  status: string;
  last_login_at: string | null;
  last_login_ip: string;
  // 强制改密状态：为 true 时登录后只能先改密（后端限制），控制台据此跳转改密页。
  must_change_password?: boolean;
  created_at: string;
  updated_at: string;
  roles?: Record<string, string[]>;
}

export type AdminTier = 'platform_admin' | 'domain_admin' | 'auditor' | 'user';

export interface PolicyRule {
  role: string;
  domain: string;
  resource: string;
  action: string;
}

export interface Role {
  id: number;
  domain_code: string;
  code: string;
  name: string;
  description: string;
  is_system: boolean;
  permissions?: PolicyRule[];
  member_count?: number;
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: number;
  domain_code: string;
  code: string;
  name: string;
  resource: string;
  action: string;
  description: string;
  created_at: string;
}

export interface OAuthClient {
  id: number;
  client_id: string;
  name: string;
  description: string;
  domain_code: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  require_pkce: boolean;
  is_confidential: boolean;
  status: string;
  created_at: string;
}

export interface PluginConfigField {
  key: string;
  label: string;
  type: 'text' | 'password' | 'url';
  required: boolean;
  placeholder: string;
  description: string;
}

export interface OAuthPluginMeta {
  type: string;
  display_name: string;
  description: string;
  default_scopes: string;
  config_fields: PluginConfigField[];
}

export interface OAuthProvider {
  id: number;
  name: string;
  plugin_type: string;
  display_name: string;
  client_id: string;
  has_client_secret: boolean;
  scopes: string;
  extra_config: Record<string, string> | null;
  auto_register: boolean;
  enabled: boolean;
  created_at: string;
}

export interface PublicProvider {
  name: string;
  plugin_type: string;
  display_name: string;
}

export interface AuditLog {
  id: number;
  actor_id: number;
  actor_username: string;
  domain_code: string;
  action: string;
  resource_type: string;
  resource_id: string;
  before_state: Record<string, unknown> | null;
  after_state: Record<string, unknown> | null;
  ip_address: string;
  user_agent: string;
  status: string;
  error_message: string;
  created_at: string;
}

export interface VersionStatus {
  app_version: string;
  expected_schema_version: number;
  current_schema_version: number;
  dirty: boolean;
  up_to_date: boolean;
  checked_at: string;
  message: string;
}

export interface VersionHistoryItem {
  id: number;
  app_version: string;
  schema_version: number;
  action: string;
  status: string;
  details: string;
  created_at: string;
}

export interface SystemSetting {
  id: number;
  setting_key: string;
  category: string;
  value: string;
  value_type: 'string' | 'int' | 'bool' | 'string_list' | 'text' | 'secret';
  label: string;
  description: string;
  updated_by: number;
  updated_at: string;
}

export interface SiteInfo {
  name: string;
  subtitle: string;
  logo_url: string;
  favicon_url: string;
  announcement_enabled: boolean;
  announcement_title: string;
  announcement_content: string;
  announcement_type: 'info' | 'success' | 'warning' | 'error';
  footer_text: string;
  allow_public_register: boolean;
  smtp_enabled: boolean;
}

export interface UserIdentity {
  id: number;
  user_id: number;
  provider_name: string;
  external_user_id: string;
  external_username: string;
  external_email: string;
  created_at: string;
  updated_at: string;
}

export interface UserPasskey {
  id: number;
  user_id: number;
  credential_id: string;
  name: string;
  last_used_at: string | null;
  created_at: string;
}

export interface TOTPStatus {
  enabled: boolean;
  verified_at: string | null;
  remaining_recovery_codes: number;
}

export interface UserSession {
  id: number;
  session_id: string;
  user_id: number;
  username?: string;
  email?: string;
  device_name: string;
  device_fingerprint: string;
  user_agent: string;
  ip_address: string;
  location: string;
  last_active_at: string;
  expires_at: string;
  created_at: string;
  is_current?: boolean;
}

export interface NotificationItem {
  id: number;
  user_id: number;
  category: 'system_message' | 'announcement' | 'system_notice';
  level: 'info' | 'warning' | 'security' | 'error';
  title: string;
  content: string;
  metadata?: Record<string, unknown> | null;
  is_read: boolean;
  read_at: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface NotificationTemplate {
  id: number;
  code: string;
  name: string;
  channel: 'email' | 'sms' | 'in_app';
  subject: string;
  body: string;
  variables: string[];
  enabled: boolean;
  updated_at: string;
}

export interface NotificationDelivery {
  id: number;
  template_code: string;
  channel: string;
  recipient: string;
  user_id: number;
  subject: string;
  status: 'sent' | 'failed' | 'bounced' | 'degraded';
  provider_name: string;
  cost_cents: number;
  error_message: string;
  bounce_reason: string;
  bounced_at: string | null;
  created_at: string;
}

export interface RiskEvent {
  id: number;
  user_id: number;
  username: string;
  ip_address: string;
  location: string;
  device_fingerprint: string;
  user_agent: string;
  risk_score: number;
  risk_level: 'low' | 'medium' | 'high';
  reasons: string[];
  action_taken: string;
  created_at: string;
}

export interface TempRoleGrant {
  id: number;
  user_id: number;
  username?: string;
  domain_code: string;
  role_code: string;
  reason: string;
  granted_by: number;
  starts_at: string;
  expires_at: string;
  status: 'pending' | 'active' | 'expired' | 'revoked';
  activated_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface UnifiedPluginConfigField {
  key: string;
  label: string;
  type: 'text' | 'password' | 'url' | 'select' | 'number' | 'bool';
  required: boolean;
  default?: string;
  placeholder?: string;
  description?: string;
  options?: { value: string; label: string }[];
}

export interface PluginDriverMeta {
  slot: 'captcha' | 'sms' | 'notification' | 'risk' | 'oauth';
  type: string;
  display_name: string;
  description: string;
  fields: UnifiedPluginConfigField[];
}

export interface PluginInstance {
  id: number;
  name: string;
  slot: 'captcha' | 'sms' | 'notification' | 'risk' | 'oauth';
  plugin_type: string;
  display_name: string;
  config: Record<string, unknown>;
  enabled: boolean;
  priority: number;
  health_status: string;
  last_checked_at: string | null;
  updated_at: string;
}

export interface CaptchaPublicConfig {
  enabled: boolean;
  mode: 'local' | 'remote' | '';
  remote_endpoint?: string;
  protect_login: boolean;
  protect_register: boolean;
  protect_otp: boolean;
}

export interface SimulationDraft {
  add_policies: PolicyRule[];
  remove_policies: PolicyRule[];
  add_roles: { user_id?: number; role: string; domain?: string }[];
  remove_roles: { user_id?: number; role: string; domain?: string }[];
}

export interface SimulationResult {
  current: boolean;
  simulated: boolean;
  effect: 'unchanged' | 'granted' | 'revoked';
  roles_before: string[];
  roles_after: string[];
  matched_policies_before: PolicyRule[];
  matched_policies_after: PolicyRule[];
}

export interface ClientIPMethodPreview {
  method: 'remote_addr' | 'x_forwarded_for' | 'x_real_ip' | 'cf_connecting_ip' | 'true_client_ip' | 'custom_header';
  label: string;
  description: string;
  source: string;
  raw_header: string;
  resolved_ip: string;
  is_public: boolean;
  from_header: boolean;
  status: 'matched' | 'direct' | 'fallback_no_header' | 'fallback_untrusted' | 'fallback_invalid' | 'not_configured';
  note: string;
  is_active: boolean;
}

export interface ClientIPPreviewResult {
  active_method: string;
  active_ip: string;
  active_is_public: boolean;
  remote_addr: string;
  remote_is_public: boolean;
  trusted_proxy_matched: boolean;
  trusted_proxies: string[];
  custom_header: string;
  options: ClientIPMethodPreview[];
}
