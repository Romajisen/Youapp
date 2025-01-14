import { ChatService } from './chat.service';
import { CreateMessageDto } from '../common/dto/create-message.dto';
export declare class ChatController {
    private readonly chatService;
    constructor(chatService: ChatService);
    sendMessage(createMessageDto: CreateMessageDto): Promise<import("./chat.schema").Message>;
    getMessages(senderId: string, receiverId: string): Promise<import("./chat.schema").Message[]>;
}
