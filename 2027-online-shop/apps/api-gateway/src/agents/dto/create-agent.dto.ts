import { IsEmail, IsIn, IsNotEmpty, IsOptional, IsString, Matches } from 'class-validator';

export class CreateAgentDto {
  @IsString() @IsNotEmpty()
  name: string;

  @IsEmail()
  email: string;

  /** URL-friendly slug, e.g. "jean-dupont". Auto-generated from name if omitted. */
  @IsOptional()
  @IsString()
  @Matches(/^[a-z0-9-]+$/, { message: 'slug must be lowercase alphanumeric with hyphens' })
  slug?: string;

  @IsOptional()
  @IsIn(['Sub-Agent', 'Agent', 'Senior Agent', 'Director'])
  level?: string;

  @IsOptional()
  @IsString()
  region?: string;

  @IsOptional()
  @IsString()
  parentId?: string;
}
