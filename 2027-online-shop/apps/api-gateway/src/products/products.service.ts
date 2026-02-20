import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma } from '@prisma/client';

@Injectable()
export class ProductsService implements OnModuleInit {
  private readonly logger = new Logger(ProductsService.name);

  constructor(private prisma: PrismaService) { }

  async onModuleInit() {
    try {
      const count = await this.prisma.product.count();
      if (count === 0) {
        this.logger.log('Seeding initial products...');
        const initialProducts: Prisma.ProductCreateInput[] = [
          {
            name: 'Neural Link Interface v4',
            price: 899,
            category: 'PERIPHERAL',
            image: '/placeholder',
            specs: ['Latency < 1ms', 'Wireless', 'Brain-Computer I/O'],
          },
          {
            name: 'Quantum Core Workstation',
            price: 4500,
            category: 'SYSTEM',
            image: '/placeholder',
            specs: ['128 Qubits', 'Liquid Cooling', 'Holographic Display'],
          },
          {
            name: 'Cyberdeck Portable MK.II',
            price: 1250,
            category: 'LAPTOP',
            image: '/placeholder',
            specs: ['Ruggedized', 'Mech Keys', 'Sat-Link Module'],
          },
          {
            name: 'Optical Data Node',
            price: 349,
            category: 'NETWORK',
            image: '/placeholder',
            specs: ['100Gbps', 'Mesh Compatible', 'Zero-Trust OS'],
          },
        ];

        for (const product of initialProducts) {
          await this.prisma.product.create({ data: product });
        }
        this.logger.log('Seeding complete.');
      }
    } catch (err) {
      this.logger.warn(`Product seeding skipped (DB unavailable): ${(err as Error).message}`);
    }
  }

  async create(createProductDto: any) {
    return this.prisma.product.create({
      data: createProductDto,
    });
  }

  async addProduct(product: Prisma.ProductCreateInput) {
    return this.prisma.product.create({
      data: product,
    });
  }

  async findAll() {
    return this.prisma.product.findMany();
  }

  async findOne(id: string) {
    return this.prisma.product.findUnique({
      where: { id },
    });
  }

  async update(id: string, updateProductDto: any) {
    return this.prisma.product.update({
      where: { id },
      data: updateProductDto,
    });
  }

  async remove(id: string) {
    return this.prisma.product.delete({
      where: { id },
    });
  }
}
