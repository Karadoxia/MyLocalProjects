import { Module } from '@nestjs/common';
import { DropshipService } from './dropship.service';
import { DropshipController } from './dropship.controller';
import { ProductsModule } from '../products/products.module';

@Module({
  imports: [ProductsModule],
  controllers: [DropshipController],
  providers: [DropshipService],
})
export class DropshipModule {}
