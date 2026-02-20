import { Controller, Get, HttpCode, HttpStatus, Post, Query } from '@nestjs/common';
import { SearchService } from './search.service';

@Controller('search')
export class SearchController {
  constructor(private readonly searchService: SearchService) {}

  /** GET /search?q=laptop&category=laptops&limit=20&offset=0 */
  @Get()
  search(
    @Query('q') q = '',
    @Query('category') category?: string,
    @Query('limit') limit = '20',
    @Query('offset') offset = '0',
  ) {
    return this.searchService.search(q, category, parseInt(limit, 10), parseInt(offset, 10));
  }

  /** POST /search/sync — index all ACTIVE products from DB into Meilisearch */
  @Post('sync')
  @HttpCode(HttpStatus.OK)
  sync() {
    return this.searchService.syncProducts();
  }
}
