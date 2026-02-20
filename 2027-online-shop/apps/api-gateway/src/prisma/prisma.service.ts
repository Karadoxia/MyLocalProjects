import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger(PrismaService.name);

    async onModuleInit() {
        try {
            await this.$connect();
        } catch (err) {
            this.logger.warn(`Database connection unavailable: ${(err as Error).message}. Continuing without DB.`);
        }
    }
}
