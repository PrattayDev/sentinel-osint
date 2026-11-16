import { OsintProvider, TargetType } from '@/types/osint';
import { AuthoritativeDnsProvider } from './dns-provider';
import { RdapRegistryProvider } from './rdap-provider';
import { TlsCertificateProvider } from './tls-provider';
import { CertificateTransparencyProvider } from './ct-provider';
import { SafeHttpSecurityProvider } from './http-provider';
import {
  RipeStatBgpProvider,
  SecurityTrailsDnsHistoryProvider,
  ShodanFullApiProvider,
  ShodanInternetDbProvider
} from './network-provider';
import {
  EmailIntelligenceProvider,
  HibpBreachProvider,
  PhoneNumberMetadataProvider,
  PublicProfileDiscoveryProvider
} from './identity-provider';
import {
  AbuseChThreatProvider,
  AbuseIpDbProvider,
  GoogleSafeBrowsingProvider,
  VirusTotalV3Provider
} from './threat-provider';
import {
  BraveWebSearchProvider,
  GleifOrganizationProvider,
  LocalFileIntelligenceProvider,
  WaybackArchiveProvider
} from './org-and-archive-provider';

const ALL_PROVIDERS: OsintProvider<string, Record<string, unknown>>[] = [
  new AuthoritativeDnsProvider() as unknown as OsintProvider<string, Record<string, unknown>>,
  new RdapRegistryProvider(),
  new TlsCertificateProvider() as unknown as OsintProvider<string, Record<string, unknown>>,
  new CertificateTransparencyProvider() as unknown as OsintProvider<string, Record<string, unknown>>,
  new SafeHttpSecurityProvider(),
  new RipeStatBgpProvider(),
  new ShodanInternetDbProvider(),
  new ShodanFullApiProvider(),
  new SecurityTrailsDnsHistoryProvider(),
  new EmailIntelligenceProvider(),
  new HibpBreachProvider(),
  new PhoneNumberMetadataProvider(),
  new PublicProfileDiscoveryProvider() as unknown as OsintProvider<string, Record<string, unknown>>,
  new AbuseChThreatProvider(),
  new VirusTotalV3Provider(),
  new AbuseIpDbProvider(),
  new GoogleSafeBrowsingProvider(),
  new WaybackArchiveProvider(),
  new GleifOrganizationProvider(),
  new BraveWebSearchProvider(),
  new LocalFileIntelligenceProvider()
];

export function getAllRegisteredProviders(): OsintProvider<
  string,
  Record<string, unknown>
>[] {
  return ALL_PROVIDERS;
}

export function getProvidersForTargetType(
  targetType: TargetType
): OsintProvider<string, Record<string, unknown>>[] {
  return ALL_PROVIDERS.filter((p) => p.supportedTypes.includes(targetType));
}

export function getProviderCatalogSummary() {
  return ALL_PROVIDERS.map((p) => ({
    id: p.id,
    name: p.name,
    category: p.category,
    supportedTypes: p.supportedTypes,
    requiresApiKey: p.requiresApiKey,
    envVarNames: p.envVarNames,
    isFreeTierAvailable: p.isFreeTierAvailable,
    rateLimitPerMinute: p.rateLimitPerMinute,
    disclosureNotice: p.disclosureNotice,
    featureIds: p.featureIds,
    status: p.isConfigured() ? ('available' as const) : ('not_configured' as const)
  }));
}
