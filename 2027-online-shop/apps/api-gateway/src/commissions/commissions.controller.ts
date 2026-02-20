import { Controller, Get, Patch, Param } from '@nestjs/common';
import { CommissionsService } from './commissions.service';

@Controller('commissions')
export class CommissionsController {
  constructor(private readonly svc: CommissionsService) {}

  /** GET /commissions — all commissions with agent info */
  @Get()
  findAll() {
    return this.svc.findAll();
  }

  /** GET /commissions/stats — aggregate totals */
  @Get('stats')
  getStats() {
    return this.svc.getStats();
  }

  /** PATCH /commissions/:id/pay — mark a commission PAID */
  @Patch(':id/pay')
  pay(@Param('id') id: string) {
    return this.svc.pay(id);
  }
}
