import { Module } from '@nestjs/common';
import { DropshipService } from './dropship.service';
import { DropshipController } from './dropship.controller';

@Module({
  controllers: [DropshipController],
  providers: [DropshipService],
})
export class DropshipModule {}
