import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateOrderDto } from './dto/update-order.dto';

@Injectable()
export class OrdersService {
  constructor(private prisma: PrismaService) {}

  async findAll(limit = 100) {
    return this.prisma.order.findMany({
      include: { items: true },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  async findOne(id: string) {
    const order = await this.prisma.order.findUnique({
      where: { id },
      include: { items: true },
    });
    if (!order) throw new NotFoundException(`Order ${id} not found`);
    return order;
  }

  async update(id: string, dto: UpdateOrderDto) {
    await this.findOne(id); // throws 404 if not found
    const updated = await this.prisma.order.update({
      where: { id },
      data: {
        ...(dto.status && { status: dto.status }),
        ...(dto.trackingNumber && { trackingNumber: dto.trackingNumber }),
        ...(dto.carrier && { carrier: dto.carrier }),
      },
      include: { items: true },
    });

    // When an order is marked DELIVERED, pay out the agent commission
    if (dto.status === 'DELIVERED') {
      const commission = await this.prisma.commission.findUnique({ where: { orderId: id } });
      if (commission && commission.status === 'PENDING') {
        await this.prisma.commission.update({
          where: { id: commission.id },
          data: { status: 'PAID' },
        });
      }
    }

    return updated;
  }

  async getStats() {
    const [totalOrders, totalRevenue, customers, statusCounts] = await Promise.all([
      this.prisma.order.count(),
      this.prisma.order.aggregate({ _sum: { total: true } }),
      this.prisma.customer.count(),
      this.prisma.order.groupBy({
        by: ['status'],
        _count: { status: true },
      }),
    ]);

    const activeStatuses = ['PAID', 'PROCESSING', 'SHIPPED'];
    const activeOrders = statusCounts
      .filter(s => activeStatuses.includes(s.status))
      .reduce((acc, s) => acc + s._count.status, 0);

    return {
      totalOrders,
      totalRevenue: totalRevenue._sum.total ?? 0,
      customers,
      activeOrders,
      statusBreakdown: statusCounts.map(s => ({
        status: s.status,
        count: s._count.status,
      })),
    };
  }
}
