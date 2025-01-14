import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({ description: 'The username of the user' })
  @IsString()
  @IsNotEmpty()
  username!: string;

  @ApiProperty({ description: 'The password of the user' })
  @IsString()
  @IsNotEmpty()
  password!: string;

  @ApiProperty({ description: 'The horoscope of the user' })
  @IsString()
  horoscope!: string;

  @ApiProperty({ description: 'The zodiac sign of the user' })
  @IsString()
  zodiac!: string;
}
