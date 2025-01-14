import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateMessageDto {
  @ApiProperty({ description: 'The content of the message' })
  @IsString()
  @IsNotEmpty()
  content!: string;

  @ApiProperty({ description: 'The ID of the sender' })
  @IsString()
  @IsNotEmpty()
  senderId!: string;

  @ApiProperty({ description: 'The ID of the receiver' })
  @IsString()
  @IsNotEmpty()
  receiverId!: string;
}
