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
import { db } from '../apps/web/lib/db';

async function main() {
    console.log('🌱 Seeding Test Data for Complex Scenario...');

    // 1. Create a Test Supplier
    const supplier = await db.supplier.upsert({
        where: { name: 'SIM_SUPPLIER' },
        update: {},
        create: { name: 'SIM_SUPPLIER', reliabilityScore: 0.95 }
    });

    // 2. Create a Test Product
    const product = await db.product.upsert({
        where: { sku: 'SKU-SCENARIO-1' },
        update: { price: 99.99 },
        create: {
            sku: 'SKU-SCENARIO-1',
            title: 'Nexus Smart Watch Pro',
            description: 'Advanced biometric tracking.',
            price: 99.99,
            supplierPrice: 65.00,
            category: 'Electronics',
            images: '[]',
            status: 'ACTIVE',
            supplierId: supplier.id
        }
    });

    // 3. Set Inventory (Low stock situation)
    await db.inventoryItem.upsert({
        where: { productId: product.id },
        update: { stockLevel: 5, reorderLevel: 10 },
        create: {
            productId: product.id,
            supplierId: supplier.id,
            externalSku: 'SUP-PRO-1',
            stockLevel: 5,
            reorderLevel: 10
        }
    });

    // 4. Set Pricing Rule
    await db.pricingRule.upsert({
        where: { category: 'Electronics' },
        update: { targetMargin: 0.40 },
        create: {
            category: 'Electronics',
            marginFloor: 0.20,
            targetMargin: 0.40
        }
    });

    console.log('✅ Scenario data ready.\n');

    console.log('🚀 Starting NEXUS Agent Swarm...');
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

    console.log('\n--- 🧪 MULTI-STAGE SIMULATION STARTING ---');

    // STAGE 1: New Purchase Task
    console.log('\n[SIM] Triggering Stage 1: New Order for SKU-SCENARIO-1');
    await systemEventBus.publish({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        source: 'user_interface',
        target: 'orchestrator',
        type: 'TASK',
        payload: {
            action: 'process_new_order',
            data: {
                sku: 'SKU-SCENARIO-1',
                customerEmail: 'ceo@example.com',
                orderId: crypto.randomUUID().split('-')[0] // Short mock ID
            }
        },
        metadata: { priority: 'high' }
    });

    // STAGE 2: Stock Check & Low Stock Response
    console.log('\n[SIM] Triggering Stage 2: Inventory Check');
    await systemEventBus.publish({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        source: 'orchestrator',
        target: 'inventory_agent',
        type: 'TASK',
        payload: {
            action: 'check_stock',
            data: { sku: 'SKU-SCENARIO-1' }
        },
        metadata: { priority: 'medium' }
    });

    // STAGE 3: Pricing Optimization (due to low stock)
    console.log('\n[SIM] Triggering Stage 3: Pricing Optimization');
    await systemEventBus.publish({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        source: 'orchestrator',
        target: 'pricing_agent',
        type: 'TASK',
        payload: {
            action: 'optimize_price',
            data: { sku: 'SKU-SCENARIO-1', currentPrice: 99.99, category: 'Electronics' }
        },
        metadata: { priority: 'medium' }
    });

    // STAGE 4: Reporting
    console.log('\n[SIM] Triggering Stage 4: Generation Daily Report');
    await systemEventBus.publish({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        source: 'orchestrator',
        target: 'reporting_agent',
        type: 'TASK',
        payload: {
            action: 'generate_report',
            data: { type: 'Sales Performance' }
        },
        metadata: { priority: 'low' }
    });

    // STAGE 5: Technical Quality Check
    console.log('\n[SIM] Triggering Stage 5: Technical Health Check');
    await systemEventBus.publish({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        source: 'orchestrator',
        target: 'quality_assurance',
        type: 'TASK',
        payload: {
            action: 'run_health_check',
            taskId: 'HEALTH-' + Date.now(),
            data: {}
        },
        metadata: { priority: 'medium' }
    });

    // Keep alive to let async handlers finish
    await new Promise(resolve => setTimeout(resolve, 8000));

    // Final Audit Check
    const events = await db.event.findMany({
        orderBy: { timestamp: 'desc' },
        take: 10
    });
    console.log('\n--- 📜 RECENT DB EVENTS (AUDIT TRAIL) ---');
    events.reverse().forEach((e: any) => console.log(`[${e.timestamp.toISOString()}] ${e.source} -> ${JSON.parse(e.payload).target || '?'}: ${e.type}`));

    console.log('\n--- 🏁 SIMULATION COMPLETE ---');
    process.exit(0);
}

main().catch((err: any) => {
    console.error('Simulation Failed:', err);
    process.exit(1);
});
