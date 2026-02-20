import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ProductsModule } from './products/products.module';
import { DropshipModule } from './dropship/dropship.module';
import { PrismaModule } from './prisma/prisma.module';
import { AgentModule } from './agent/agent.module';
import { CheckoutModule } from './checkout/checkout.module';
import { OrdersModule } from './orders/orders.module';
import { AgentsModule } from './agents/agents.module';
import { SearchModule } from './search/search.module';
import { CommissionsModule } from './commissions/commissions.module';

@Module({
  imports: [
    ProductsModule, DropshipModule, PrismaModule,
    AgentModule, CheckoutModule, OrdersModule,
    AgentsModule, SearchModule, CommissionsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
