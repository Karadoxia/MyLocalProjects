import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class CommissionsService {
  constructor(private prisma: PrismaService) {}

  async findAll() {
    return this.prisma.commission.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        agent: { select: { id: true, name: true, email: true, slug: true, tier: true } },
      },
    });
  }

  async pay(id: string) {
    const commission = await this.prisma.commission.findUnique({ where: { id } });
    if (!commission) throw new NotFoundException(`Commission ${id} not found`);
    if (commission.status === 'PAID') return commission; // idempotent

    return this.prisma.commission.update({
      where: { id },
      data: { status: 'PAID' },
      include: {
        agent: { select: { id: true, name: true, email: true, slug: true, tier: true } },
      },
    });
  }

  async getStats() {
    const [total, pending, paid] = await Promise.all([
      this.prisma.commission.aggregate({ _sum: { amount: true }, _count: true }),
      this.prisma.commission.aggregate({
        where: { status: 'PENDING' },
        _sum: { amount: true },
        _count: true,
      }),
      this.prisma.commission.aggregate({
        where: { status: 'PAID' },
        _sum: { amount: true },
        _count: true,
      }),
    ]);

    return {
      totalAmount: total._sum.amount ?? 0,
      totalCount: total._count,
      pendingAmount: pending._sum.amount ?? 0,
      pendingCount: pending._count,
      paidAmount: paid._sum.amount ?? 0,
      paidCount: paid._count,
    };
  }
}
