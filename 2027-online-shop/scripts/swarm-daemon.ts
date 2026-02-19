import * as dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// ES Module __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, '../apps/web/.env') });

import { OrchestratorAgent } from '../apps/web/lib/agents/orchestrator';
import { InventoryAgent } from '../apps/web/lib/agents/operations/inventory';
import { FulfillmentAgent } from '../apps/web/lib/agents/operations/fulfillment';
import { PricingAgent } from '../apps/web/lib/agents/intelligence/pricing';
import { CustomerAgent } from '../apps/web/lib/agents/commerce/customer';
import { CatalogAgent } from '../apps/web/lib/agents/commerce/catalog';
import { ReportingAgent } from '../apps/web/lib/agents/intelligence/reporting';
import { QualityAgent } from '../apps/web/lib/agents/it-rd/QualityAgent';
import { systemEventBus } from '../apps/web/lib/agents/core/EventBus';

async function main() {
    console.log('🚀 Starting NEXUS Agent Swarm (Daemon Mode)...');

    // Start Cross-Process Bridge
    systemEventBus.startPolling(2000);

    // Initialize agents
    const agents = [
        new OrchestratorAgent(),
        new InventoryAgent(),
        new FulfillmentAgent(),
        new PricingAgent(),
        new CustomerAgent(),
        new CatalogAgent(),
        new ReportingAgent(),
        new QualityAgent()
    ];

    console.log(`📡 Swarm is live with ${agents.length} agents listening.`);
    console.log('Use CTRL+C to stop (if running manually)');

    // Keep alive indefinitely
    process.stdin.resume();

    // Handle graceful shutdown
    process.on('SIGINT', () => {
        console.log('\n🛑 Shutting down swarm...');
        process.exit(0);
    });
}

main().catch((err: any) => {
    console.error('Swarm Daemon Failed:', err);
    process.exit(1);
});
