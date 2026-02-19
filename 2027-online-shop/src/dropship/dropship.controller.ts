import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { DropshipService } from './dropship.service';
import { CreateDropshipDto } from './dto/create-dropship.dto';
import { UpdateDropshipDto } from './dto/update-dropship.dto';

@Controller('dropship')
export class DropshipController {
  constructor(private readonly dropshipService: DropshipService) {}

  @Post()
  create(@Body() createDropshipDto: CreateDropshipDto) {
    return this.dropshipService.create(createDropshipDto);
  }

  @Get()
  findAll() {
    return this.dropshipService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.dropshipService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateDropshipDto: UpdateDropshipDto) {
    return this.dropshipService.update(+id, updateDropshipDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.dropshipService.remove(+id);
  }
}
