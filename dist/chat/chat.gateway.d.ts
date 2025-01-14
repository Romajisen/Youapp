import { Server, Socket } from 'socket.io';
import { ChatService } from './chat.service';
import { CreateMessageDto } from '../common/dto/create-message.dto';
export declare class ChatGateway {
    private readonly chatService;
    server: Server;
    constructor(chatService: ChatService);
    handleMessage(createMessageDto: CreateMessageDto, client: Socket): Promise<void>;
}
