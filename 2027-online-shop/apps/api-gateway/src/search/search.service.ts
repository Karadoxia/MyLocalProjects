import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { MeiliSearch } from 'meilisearch';

const PRODUCTS_INDEX = 'products';

@Injectable()
export class SearchService implements OnModuleInit {
  private readonly logger = new Logger(SearchService.name);
  private meili: InstanceType<typeof MeiliSearch>;
  private ready = false;

  constructor(private prisma: PrismaService) {
    const host = process.env.MEILI_URL ?? 'http://localhost:7700';
    const apiKey = process.env.MEILI_MASTER_KEY ?? '';
    this.meili = new MeiliSearch({ host, apiKey });
  }

  async onModuleInit() {
    try {
      const index = this.meili.index(PRODUCTS_INDEX);
      await index.updateSettings({
        searchableAttributes: ['title', 'description', 'category', 'sku'],
        filterableAttributes: ['category', 'status', 'price'],
        sortableAttributes: ['price', 'createdAt'],
        displayedAttributes: ['id', 'sku', 'title', 'description', 'price', 'supplierPrice', 'category', 'images', 'status'],
      });
      this.ready = true;
      this.logger.log('Meilisearch index ready — syncing products...');
      await this.syncProducts();
    } catch (err) {
      this.logger.warn(`Meilisearch unavailable: ${err.message}. Search will fall back to DB.`);
    }
  }

  async syncProducts(): Promise<{ indexed: number }> {
    const products = await this.prisma.product.findMany({ where: { status: 'ACTIVE' } });
    const docs = products.map(p => ({ ...p }));
    await this.meili.index(PRODUCTS_INDEX).addDocuments(docs, { primaryKey: 'id' });
    this.logger.log(`Synced ${docs.length} products to Meilisearch`);
    return { indexed: docs.length };
  }

  async search(query: string, category?: string, limit = 20, offset = 0) {
    if (!this.ready) {
      return this.dbFallback(query, category, limit, offset);
    }

    try {
      const filter = category ? [`category = "${category}"`] : undefined;
      const result = await this.meili.index(PRODUCTS_INDEX).search(query, {
        limit,
        offset,
        filter,
      });
      return {
        products: result.hits,
        total: result.estimatedTotalHits ?? result.hits.length,
        source: 'meilisearch',
      };
    } catch (err) {
      this.logger.warn(`Meilisearch query failed: ${err.message}. Falling back to DB.`);
      return this.dbFallback(query, category, limit, offset);
    }
  }

  private async dbFallback(query: string, category?: string, limit = 20, offset = 0) {
    const where: any = { status: 'ACTIVE' };
    if (category) where.category = category;
    if (query) {
      where.OR = [
        { title: { contains: query, mode: 'insensitive' } },
        { description: { contains: query, mode: 'insensitive' } },
        { sku: { contains: query, mode: 'insensitive' } },
      ];
    }
    const [products, total] = await Promise.all([
      this.prisma.product.findMany({ where, skip: offset, take: limit }),
      this.prisma.product.count({ where }),
    ]);
    return { products, total, source: 'database' };
  }
}
