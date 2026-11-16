import { NextResponse } from 'next/server';
import { getProviderCatalogSummary } from '@/lib/providers/registry';
import { getSupabaseAdminClient } from '@/lib/db/repository';

export const dynamic = 'force-dynamic';

export async function GET() {
  const catalog = getProviderCatalogSummary();
  const availableCount = catalog.filter((p) => p.status === 'available').length;
  const notConfiguredCount = catalog.filter(
    (p) => p.status === 'not_configured'
  ).length;
  const supabaseConfigured = Boolean(getSupabaseAdminClient());

  return NextResponse.json({
    status: 'healthy',
    platform: 'Sentinel OSINT',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    persistenceMode: 'local_json_repository',
    supabaseEnvConfigured: supabaseConfigured,
    providers: {
      total: catalog.length,
      available: availableCount,
      notConfigured: notConfiguredCount
    }
  });
}
