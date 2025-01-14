import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Message } from './chat.schema';
import { CreateMessageDto } from '../common/dto/create-message.dto';

@Injectable()
export class ChatService {
  constructor(@InjectModel(Message.name) private messageModel: Model<Message>) {}

  async sendMessage(createMessageDto: CreateMessageDto): Promise<Message> {
    const createdMessage = new this.messageModel(createMessageDto);
    return createdMessage.save();
  }
  
  async getMessages(senderId: string, receiverId: string): Promise<Message[]> { 
    return this.messageModel.find({ $or: [ { senderId, receiverId }, { senderId: receiverId, receiverId: senderId }, ], }).exec(); 
  }

  async getAllMessages(): Promise<Message[]> {
    return this.messageModel.find().exec();
  }
}
