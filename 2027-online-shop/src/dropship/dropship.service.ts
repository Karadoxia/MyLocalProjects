import { Injectable } from '@nestjs/common';
import { CreateDropshipDto } from './dto/create-dropship.dto';
import { UpdateDropshipDto } from './dto/update-dropship.dto';

@Injectable()
export class DropshipService {
  create(createDropshipDto: CreateDropshipDto) {
    return 'This action adds a new dropship';
  }

  findAll() {
    return `This action returns all dropship`;
  }

  findOne(id: number) {
    return `This action returns a #${id} dropship`;
  }

  update(id: number, updateDropshipDto: UpdateDropshipDto) {
    return `This action updates a #${id} dropship`;
  }

  remove(id: number) {
    return `This action removes a #${id} dropship`;
  }
}
