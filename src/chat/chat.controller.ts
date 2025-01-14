import { Controller, Post, Body, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ChatService } from './chat.service';
import { CreateMessageDto } from '../common/dto/create-message.dto';

@ApiTags('chat')
@Controller('chat')
export class ChatController {
  constructor(private readonly chatService: ChatService) {}

  @Post('send')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Send a chat message' })
  @ApiResponse({ status: 201, description: 'The message has been successfully sent.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async sendMessage(@Body() createMessageDto: CreateMessageDto) {
    return this.chatService.sendMessage(createMessageDto);
  }

  @Get('messages')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Get chat messages' })
  @ApiResponse({ status: 200, description: 'The messages have been successfully retrieved.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async getMessages(@Query('senderId') senderId: string, @Query('receiverId') receiverId: string) {
    return this.chatService.getMessages(senderId, receiverId);
  }
}
