import {
  Controller, Get, Patch, Param, Body, Query, HttpCode, HttpStatus,
} from '@nestjs/common';
import { OrdersService } from './orders.service';
import { UpdateOrderDto } from './dto/update-order.dto';

@Controller('orders')
export class OrdersController {
  constructor(private readonly ordersService: OrdersService) {}

  /** GET /orders — all orders, newest first (admin view) */
  @Get()
  findAll(@Query('limit') limit?: string) {
    return this.ordersService.findAll(limit ? parseInt(limit, 10) : 100);
  }

  /** GET /orders/stats — revenue, counts, active orders */
  @Get('stats')
  getStats() {
    return this.ordersService.getStats();
  }

  /** GET /orders/:id — single order with items */
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.ordersService.findOne(id);
  }

  /** PATCH /orders/:id — update status, trackingNumber, carrier */
  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  update(@Param('id') id: string, @Body() dto: UpdateOrderDto) {
    return this.ordersService.update(id, dto);
  }
}
