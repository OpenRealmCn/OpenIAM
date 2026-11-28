import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api } from '../api/client';
import { SiteInfo } from '../types/api';

const DEFAULT_SITE_INFO: SiteInfo = {
  name: 'OpenIAM',
  subtitle: '统一身份与访问管理平台',
  logo_url: '/logo.png',
  favicon_url: '/logo.png',
  announcement_enabled: false,
  announcement_title: '',
  announcement_content: '',
  announcement_type: 'info',
  footer_text: '© OpenRealm · OpenIAM',
  allow_public_register: true,
  smtp_enabled: false,
};

interface SiteContextValue {
  siteInfo: SiteInfo;
  refreshSiteInfo: () => Promise<void>;
}

const SiteContext = createContext<SiteContextValue | null>(null);

export const SiteProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [siteInfo, setSiteInfo] = useState<SiteInfo>(DEFAULT_SITE_INFO);

  const applyDocumentBranding = useCallback((info: SiteInfo) => {
    const title = info.subtitle ? `${info.name} - ${info.subtitle}` : info.name || 'OpenIAM';
    document.title = title;

    const iconHref = info.favicon_url || info.logo_url || '/logo.png';
    let link = document.querySelector<HTMLLinkElement>("link[rel~='icon']");
    if (!link) {
      link = document.createElement('link');
      link.rel = 'icon';
      document.head.appendChild(link);
    }
    link.href = iconHref;
  }, []);

  const refreshSiteInfo = useCallback(async () => {
    try {
      const data = await api.site.info();
      const merged: SiteInfo = {
        ...DEFAULT_SITE_INFO,
        ...data,
        logo_url: data?.logo_url || DEFAULT_SITE_INFO.logo_url,
        favicon_url: data?.favicon_url || data?.logo_url || DEFAULT_SITE_INFO.favicon_url,
      };
      setSiteInfo(merged);
      applyDocumentBranding(merged);
    } catch {
      applyDocumentBranding(DEFAULT_SITE_INFO);
    }
  }, [applyDocumentBranding]);

  useEffect(() => {
    refreshSiteInfo();
  }, [refreshSiteInfo]);

  return (
    <SiteContext.Provider value={{ siteInfo, refreshSiteInfo }}>
      {children}
    </SiteContext.Provider>
  );
};

export function useSite(): SiteContextValue {
  const ctx = useContext(SiteContext);
  if (!ctx) {
    throw new Error('useSite must be used inside SiteProvider');
  }
  return ctx;
}
