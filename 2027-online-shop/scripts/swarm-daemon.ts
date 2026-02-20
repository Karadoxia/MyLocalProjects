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
import { NegotiationAgent } from '../apps/web/lib/agents/it-rd/NegotiationAgent';
import { ProcurementAgent } from '../apps/web/lib/agents/operations/procurement';
import { systemEventBus } from '../apps/web/lib/agents/core/EventBus';

// Supplier adapters
import { supplierRegistry } from '../apps/web/lib/suppliers/registry';
import { CJDropshippingAdapter } from '../apps/web/lib/suppliers/cj-dropshipping';
import { AliExpressAdapter } from '../apps/web/lib/suppliers/aliexpress';
import { BigBuyAdapter } from '../apps/web/lib/suppliers/bigbuy';

// DB for supplier seeding
import { db } from '../apps/web/lib/db';

async function seedSuppliers() {
    const suppliers = [
        { name: 'CJDropshipping', apiEndpoint: 'https://api.cjdropshipping.com' },
        { name: 'AliExpress', apiEndpoint: 'https://api-sg.aliexpress.com' },
        { name: 'BigBuy', apiEndpoint: 'https://api.bigbuy.eu' },
    ];

    for (const s of suppliers) {
        await db.supplier.upsert({
            where: { name: s.name },
            update: { apiEndpoint: s.apiEndpoint },
            create: {
                name: s.name,
                apiEndpoint: s.apiEndpoint,
                reliabilityScore: 1.0,
                avgDeliveryDays: s.name === 'BigBuy' ? 3 : s.name === 'CJDropshipping' ? 7 : 12,
            }
        });
    }
    console.log(`📋 Supplier DB seeded (${suppliers.length} suppliers)`);
}

async function main() {
    console.log('🚀 Starting NEXUS Agent Swarm (Daemon Mode)...');

    // Seed supplier records
    await seedSuppliers();

    // Register supplier adapters
    supplierRegistry.register(new CJDropshippingAdapter({ apiKey: '', user: '' }));
    supplierRegistry.register(new AliExpressAdapter({ apiKey: process.env.ALIEXPRESS_APP_KEY }));
    supplierRegistry.register(new BigBuyAdapter({ apiKey: process.env.BIGBUY_API_KEY }));
    console.log(`🔌 Supplier Registry: ${supplierRegistry.getNames().join(', ')}`);

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
        new QualityAgent(),
        new NegotiationAgent(),
        new ProcurementAgent(),
    ];

    // Start QualityAgent monitoring (only in daemon context, not Next.js)
    const qualityAgent = agents.find(a => a.name === 'quality_assurance') as QualityAgent;
    if (qualityAgent) {
        qualityAgent.startMonitoring(300000); // 5 minutes
    }

    console.log(`📡 Swarm is live with ${agents.length} agents listening.`);
    console.log('Use CTRL+C or send SIGTERM to stop.');

    // Keep alive indefinitely
    process.stdin.resume();

    // Graceful shutdown handler
    const shutdown = async (signal: string) => {
        console.log(`\n🛑 [${signal}] Shutting down swarm gracefully...`);

        // Stop EventBus polling
        systemEventBus.stopPolling();

        // Shutdown all agents
        for (const agent of agents) {
            try {
                await agent.shutdown();
            } catch (err) {
                console.error(`Failed to shutdown ${agent.name}:`, err);
            }
        }

        console.log('✅ All agents shut down. Exiting.');
        process.exit(0);
    };

    // Handle both SIGINT (Ctrl+C) and SIGTERM (PM2/Docker/systemd)
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

    // Handle uncaught exceptions gracefully
    process.on('uncaughtException', (err) => {
        console.error('💥 Uncaught Exception:', err);
        shutdown('UNCAUGHT_EXCEPTION');
    });
}

main().catch((err: any) => {
    console.error('Swarm Daemon Failed:', err);
    process.exit(1);
});

