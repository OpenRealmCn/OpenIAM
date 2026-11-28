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
  value_type: 'string' | 'int' | 'bool' | 'string_list';
  label: string;
  description: string;
  updated_by: number;
  updated_at: string;
}
