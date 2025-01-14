import { Model } from 'mongoose';
import { Message } from './chat.schema';
import { CreateMessageDto } from '../common/dto/create-message.dto';
export declare class ChatService {
    private messageModel;
    constructor(messageModel: Model<Message>);
    sendMessage(createMessageDto: CreateMessageDto): Promise<Message>;
    getMessages(senderId: string, receiverId: string): Promise<Message[]>;
    getAllMessages(): Promise<Message[]>;
}
