import { Body, Controller, Get, HttpCode, HttpStatus, Param, Post } from '@nestjs/common';
import { AgentsService } from './agents.service';
import { CreateAgentDto } from './dto/create-agent.dto';

@Controller('agents')
export class AgentsController {
  constructor(private readonly agentsService: AgentsService) {}

  /** GET /agents — list all agents with commission totals */
  @Get()
  findAll() {
    return this.agentsService.findAll();
  }

  /** GET /agents/:slug — agent profile + commissions + hierarchy */
  @Get(':slug')
  findOne(@Param('slug') slug: string) {
    return this.agentsService.findBySlug(slug);
  }

  /** GET /agents/:slug/stats — revenue, earnings, order count */
  @Get(':slug/stats')
  getStats(@Param('slug') slug: string) {
    return this.agentsService.getStats(slug);
  }

  /** POST /agents — onboard a new agent */
  @Post()
  @HttpCode(HttpStatus.CREATED)
  create(@Body() dto: CreateAgentDto) {
    return this.agentsService.create(dto);
  }
}
