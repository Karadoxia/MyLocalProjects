import { Controller, Post, Body } from '@nestjs/common';
import { DropshipService } from './dropship.service';

@Controller('dropship')
export class DropshipController {
  constructor(private readonly dropshipService: DropshipService) {}

  @Post('import')
  importProduct(@Body('url') url: string) {
    return this.dropshipService.importProduct(url);
  }
}
