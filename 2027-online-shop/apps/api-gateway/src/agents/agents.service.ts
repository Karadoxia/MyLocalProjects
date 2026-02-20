import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateAgentDto } from './dto/create-agent.dto';

@Injectable()
export class AgentsService {
  constructor(private prisma: PrismaService) {}

  private slugify(name: string): string {
    return name
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  private commissionRate(level: string): number {
    const rates: Record<string, number> = {
      'Sub-Agent': 0.06,
      'Agent': 0.07,
      'Senior Agent': 0.08,
      'Director': 0.10,
    };
    return rates[level] ?? 0.06;
  }

  private tierFromRate(rate: number): string {
    if (rate >= 0.10) return 'platinum';
    if (rate >= 0.08) return 'gold';
    if (rate >= 0.07) return 'silver';
    return 'bronze';
  }

  async findAll() {
    return this.prisma.agent.findMany({
      include: {
        commissions: { select: { amount: true, status: true } },
        subAgents: { select: { id: true, name: true, slug: true, level: true, tier: true } },
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findBySlug(slug: string) {
    const agent = await this.prisma.agent.findUnique({
      where: { slug },
      include: {
        commissions: { orderBy: { createdAt: 'desc' }, take: 20 },
        subAgents: { select: { id: true, name: true, slug: true, level: true, tier: true, status: true } },
        parent: { select: { id: true, name: true, slug: true, level: true } },
      },
    });
    if (!agent) throw new NotFoundException(`Agent "${slug}" not found`);
    return agent;
  }

  async create(dto: CreateAgentDto) {
    const slug = dto.slug ?? this.slugify(dto.name);
    const existing = await this.prisma.agent.findUnique({ where: { slug } });
    if (existing) throw new ConflictException(`Agent slug "${slug}" already taken`);

    const level = dto.level ?? 'Sub-Agent';
    const rate = this.commissionRate(level);
    const tier = this.tierFromRate(rate);

    return this.prisma.agent.create({
      data: {
        slug,
        name: dto.name,
        email: dto.email,
        level,
        tier,
        commissionRate: rate,
        region: dto.region ?? '',
        parentId: dto.parentId ?? null,
      },
    });
  }

  async getStats(slug: string) {
    const agent = await this.prisma.agent.findUnique({
      where: { slug },
      include: { commissions: true },
    });
    if (!agent) throw new NotFoundException(`Agent "${slug}" not found`);

    const totalEarned = agent.commissions
      .filter(c => c.status === 'PAID')
      .reduce((sum, c) => sum + c.amount, 0);
    const pendingEarnings = agent.commissions
      .filter(c => c.status === 'PENDING')
      .reduce((sum, c) => sum + c.amount, 0);
    const totalOrders = agent.commissions.length;
    const totalRevenue = agent.commissions.reduce((sum, c) => sum + c.orderTotal, 0);

    return { agent, totalEarned, pendingEarnings, totalOrders, totalRevenue };
  }
}
