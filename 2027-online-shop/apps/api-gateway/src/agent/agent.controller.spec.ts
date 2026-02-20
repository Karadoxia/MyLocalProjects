import { Test, TestingModule } from '@nestjs/testing';
import { AgentController } from './agent.controller';
import { AgentService } from './agent.service';

describe('AgentController', () => {
    let controller: AgentController;
    let service: AgentService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [AgentController],
            providers: [AgentService],
        }).compile();

        controller = module.get<AgentController>(AgentController);
        service = module.get<AgentService>(AgentService);
    });

    describe('chat', () => {
        it('should return market reply for market keyword', () => {
            const result = controller.chat({ message: 'Tell me about the market opportunity' });
            expect(result).toHaveProperty('reply');
            expect((result as { reply: string }).reply).toContain('Windows 10');
        });

        it('should return supplier reply for supplier keyword', () => {
            const result = controller.chat({ message: 'Who are our suppliers?' });
            expect(result).toHaveProperty('reply');
            expect((result as { reply: string }).reply).toContain('Ingram Micro');
        });

        it('should return strategy reply for strategy keyword', () => {
            const result = controller.chat({ message: 'What is our strategy?' });
            expect(result).toHaveProperty('reply');
            expect((result as { reply: string }).reply).toContain('Ingram Micro');
        });

        it('should return default reply for unknown message', () => {
            const result = controller.chat({ message: 'hello' });
            expect(result).toHaveProperty('reply');
            expect((result as { reply: string }).reply).toContain('Strategic Advisor');
        });
    });

    describe('checkCompatibility', () => {
        it('should mark incompatible when TPM < 2.0', () => {
            const result = controller.checkCompatibility({ cpu: 'Intel Core i5-8400', ramGb: 8, tpmVersion: 1.2 });
            expect(result).toHaveProperty('compatible', false);
            expect((result as { reasons: string[] }).reasons).toEqual(
                expect.arrayContaining([expect.stringContaining('TPM 2.0')])
            );
        });

        it('should mark incompatible when RAM < 4GB', () => {
            const result = controller.checkCompatibility({ cpu: 'Intel Core i5-8400', ramGb: 2, tpmVersion: 2.0 });
            expect(result).toHaveProperty('compatible', false);
        });

        it('should mark incompatible for 7th-gen Intel CPU', () => {
            const result = controller.checkCompatibility({ cpu: 'Intel Core i7-7700', ramGb: 8, tpmVersion: 2.0 });
            expect(result).toHaveProperty('compatible', false);
            expect((result as { reasons: string[] }).reasons).toEqual(
                expect.arrayContaining([expect.stringContaining('7th Gen')])
            );
        });

        it('should mark compatible for a valid config', () => {
            const result = controller.checkCompatibility({ cpu: 'Intel Core i5-8400', ramGb: 8, tpmVersion: 2.0 });
            expect(result).toHaveProperty('compatible', true);
        });
    });

    describe('prompt', () => {
        it('should return product context for product keyword', () => {
            const result = controller.prompt({ prompt: 'Show me your product catalog' });
            expect(result).toHaveProperty('response');
            expect(result).toHaveProperty('context', 'product-catalog');
        });

        it('should return pricing context for price keyword', () => {
            const result = controller.prompt({ prompt: 'What is the price?' });
            expect(result).toHaveProperty('context', 'pricing');
        });

        it('should return fulfillment context for shipping keyword', () => {
            const result = controller.prompt({ prompt: 'How does shipping work?' });
            expect(result).toHaveProperty('context', 'fulfillment');
        });

        it('should return general context for unknown prompt', () => {
            const result = controller.prompt({ prompt: 'Random question' });
            expect(result).toHaveProperty('context', 'general');
        });
    });

    describe('scrape', () => {
        it('should return scraped data for a valid URL', () => {
            const result = controller.scrape({ url: 'https://example.com/products' });
            expect(result).toHaveProperty('url', 'https://example.com/products');
            expect(result).toHaveProperty('source', 'example.com');
            expect(result).toHaveProperty('extracted');
        });

        it('should return error for an invalid URL', () => {
            const result = controller.scrape({ url: 'not-a-url' });
            expect(result).toHaveProperty('error');
        });

        it('should include items array in extracted data', () => {
            const result = controller.scrape({ url: 'https://supplier.io/catalog' }) as {
                extracted: { items: unknown[] };
            };
            expect(Array.isArray(result.extracted.items)).toBe(true);
        });
    });

    describe('demo', () => {
        it('should return agent capabilities', () => {
            const result = controller.demo() as {
                agent: string;
                capabilities: { endpoint: string; description: string }[];
                status: string;
            };
            expect(result).toHaveProperty('agent');
            expect(Array.isArray(result.capabilities)).toBe(true);
            expect(result.capabilities.length).toBeGreaterThan(0);
            expect(result).toHaveProperty('status', 'operational');
        });

        it('should list all agent endpoints in capabilities', () => {
            const result = controller.demo() as {
                capabilities: { endpoint: string }[];
            };
            const endpoints = result.capabilities.map((c) => c.endpoint);
            expect(endpoints).toEqual(expect.arrayContaining([
                expect.stringContaining('/agent/prompt'),
                expect.stringContaining('/agent/scrape'),
                expect.stringContaining('/agent/demo'),
            ]));
        });

        it('should include market intel summary', () => {
            const result = controller.demo() as { marketIntelSummary: string };
            expect(typeof result.marketIntelSummary).toBe('string');
            expect(result.marketIntelSummary.length).toBeGreaterThan(0);
        });
    });

    describe('AgentService unit', () => {
        it('service should be defined', () => {
            expect(service).toBeDefined();
        });

        it('scrape should handle URL with path', () => {
            const result = service.scrape('https://shop.example.org/items/123') as { source: string };
            expect(result.source).toBe('shop.example.org');
        });
    });
});
