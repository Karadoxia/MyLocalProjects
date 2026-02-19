import { PartialType } from '@nestjs/mapped-types';
import { CreateDropshipDto } from './create-dropship.dto';

export class UpdateDropshipDto extends PartialType(CreateDropshipDto) {}
