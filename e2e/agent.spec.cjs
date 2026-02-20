// @ts-check
const { test, expect } = require('@playwright/test');

/**
 * Playwright E2E tests for /agent endpoints.
 * The webServer in playwright.config.cjs starts the compiled NestJS server
 * before these tests run.
 */

test.describe('GET /agent/demo', () => {
  test('returns 200 with agent capabilities', async ({ request }) => {
    const res = await request.get('/agent/demo');
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body).toHaveProperty('agent');
    expect(body).toHaveProperty('status', 'operational');
    expect(Array.isArray(body.capabilities)).toBe(true);
    expect(body.capabilities.length).toBeGreaterThan(0);
  });

  test('lists prompt, scrape, and demo endpoints in capabilities', async ({ request }) => {
    const res = await request.get('/agent/demo');
    const body = await res.json();

    const endpoints = body.capabilities.map((/** @type {{ endpoint: string }} */ c) => c.endpoint);
    expect(endpoints.some((/** @type {string} */ e) => e.includes('/agent/prompt'))).toBe(true);
    expect(endpoints.some((/** @type {string} */ e) => e.includes('/agent/scrape'))).toBe(true);
    expect(endpoints.some((/** @type {string} */ e) => e.includes('/agent/demo'))).toBe(true);
  });

  test('includes marketIntelSummary string', async ({ request }) => {
    const res = await request.get('/agent/demo');
    const body = await res.json();
    expect(typeof body.marketIntelSummary).toBe('string');
    expect(body.marketIntelSummary.length).toBeGreaterThan(0);
  });
});

test.describe('POST /agent/prompt', () => {
  test('returns product-catalog context for product query', async ({ request }) => {
    const res = await request.post('/agent/prompt', {
      data: { prompt: 'Show me your product catalog' },
    });
    expect(res.status()).toBe(201);

    const body = await res.json();
    expect(body).toHaveProperty('response');
    expect(body).toHaveProperty('context', 'product-catalog');
  });

  test('returns pricing context for price query', async ({ request }) => {
    const res = await request.post('/agent/prompt', {
      data: { prompt: 'What does it cost?' },
    });
    const body = await res.json();
    expect(body).toHaveProperty('context', 'pricing');
  });

  test('returns fulfillment context for shipping query', async ({ request }) => {
    const res = await request.post('/agent/prompt', {
      data: { prompt: 'How long does shipping take?' },
    });
    const body = await res.json();
    expect(body).toHaveProperty('context', 'fulfillment');
  });

  test('returns general context for unrecognised prompt', async ({ request }) => {
    const res = await request.post('/agent/prompt', {
      data: { prompt: 'something completely different' },
    });
    const body = await res.json();
    expect(body).toHaveProperty('context', 'general');
  });
});

test.describe('POST /agent/scrape', () => {
  test('returns extracted data for a valid URL', async ({ request }) => {
    const res = await request.post('/agent/scrape', {
      data: { url: 'https://example.com/products' },
    });
    expect(res.status()).toBe(201);

    const body = await res.json();
    expect(body).toHaveProperty('url', 'https://example.com/products');
    expect(body).toHaveProperty('source', 'example.com');
    expect(body).toHaveProperty('extracted');
    expect(Array.isArray(body.extracted.items)).toBe(true);
  });

  test('returns error object for an invalid URL', async ({ request }) => {
    const res = await request.post('/agent/scrape', {
      data: { url: 'not-a-valid-url' },
    });
    expect(res.status()).toBe(201);

    const body = await res.json();
    expect(body).toHaveProperty('error');
  });

  test('includes scrapedAt timestamp in extracted data', async ({ request }) => {
    const res = await request.post('/agent/scrape', {
      data: { url: 'https://supplier.io/items' },
    });
    const body = await res.json();
    expect(body.extracted).toHaveProperty('scrapedAt');
    expect(new Date(body.extracted.scrapedAt).getTime()).not.toBeNaN();
  });
});

test.describe('POST /agent/chat (existing)', () => {
  test('returns market reply for market keyword', async ({ request }) => {
    const res = await request.post('/agent/chat', {
      data: { message: 'Tell me about the market opportunity' },
    });
    expect(res.status()).toBe(201);

    const body = await res.json();
    expect(body).toHaveProperty('reply');
    expect(body.reply).toContain('Windows 10');
  });

  test('returns default reply for unknown message', async ({ request }) => {
    const res = await request.post('/agent/chat', {
      data: { message: 'hello there' },
    });
    const body = await res.json();
    expect(body.reply).toContain('Strategic Advisor');
  });
});
