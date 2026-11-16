/**
 * Sentinel OSINT — Standalone Background Worker
 * Executes queued or long-running OSINT investigations outside serverless execution time limits.
 */
import { getProviderCatalogSummary } from '../src/lib/providers/registry';

async function startWorker() {
  const catalog = getProviderCatalogSummary();
  const available = catalog.filter((p) => p.status === 'available').length;
  console.log(
    `[Sentinel Worker] Online at ${new Date().toISOString()} — ${available}/${catalog.length} providers ready.`
  );
  console.log(
    '[Sentinel Worker] Listening for queued background investigation jobs...'
  );
}

if (require.main === module) {
  startWorker().catch((err) => {
    console.error('[Sentinel Worker] Fatal startup error:', err);
    process.exit(1);
  });
}

export { startWorker };
