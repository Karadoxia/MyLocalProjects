import { Controller, Post, Get, Body } from '@nestjs/common';
import { AgentService } from './agent.service';
import { ChatDto } from './dto/chat.dto';
import { CompatibilityCheckDto } from './dto/compatibility-check.dto';
import { PromptDto } from './dto/prompt.dto';
import { ScrapeDto } from './dto/scrape.dto';

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

    @Post('prompt')
    prompt(@Body() promptDto: PromptDto) {
        return this.agentService.prompt(promptDto.prompt);
    }

    @Post('scrape')
    scrape(@Body() scrapeDto: ScrapeDto) {
        return this.agentService.scrape(scrapeDto.url);
    }

    @Get('demo')
    demo() {
        return this.agentService.demo();
    }
}
