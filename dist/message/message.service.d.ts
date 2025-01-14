import { Model } from 'mongoose';
import { Message } from './message.schema';
import { CreateMessageDto } from '../common/dto/create-message.dto';
export declare class MessageService {
    private messageModel;
    constructor(messageModel: Model<Message>);
    create(createMessageDto: CreateMessageDto): Promise<Message>;
    findAll(): Promise<Message[]>;
    findByUser(userId: string): Promise<Message[]>;
}
