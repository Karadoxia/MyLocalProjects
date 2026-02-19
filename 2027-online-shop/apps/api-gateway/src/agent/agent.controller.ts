import { Controller, Post, Body } from '@nestjs/common';
import { AgentService } from './agent.service';
import { ChatDto } from './dto/chat.dto';
import { CompatibilityCheckDto } from './dto/compatibility-check.dto';

@Controller('agent')
export class AgentController {
    constructor(private readonly agentService: AgentService) { }

    @Post('chat')
    chat(@Body() chatDto: ChatDto) {
        return this.agentService.chat(chatDto.message);
    }

    @Post('check-compatibility')
    checkCompatibility(@Body() checkDto: CompatibilityCheckDto) {
        return this.agentService.checkCompatibility(checkDto);
    }
}
