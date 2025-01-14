import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Message } from './message.schema';
import { CreateMessageDto } from '../common/dto/create-message.dto';

@Injectable()
export class MessageService {
  constructor(@InjectModel(Message.name) private messageModel: Model<Message>) {}

  async create(createMessageDto: CreateMessageDto): Promise<Message> {
    const createdMessage = new this.messageModel(createMessageDto);
    return createdMessage.save();
  }

  async findAll(): Promise<Message[]> {
    return this.messageModel.find().exec();
  }

  async findByUser(userId: string): Promise<Message[]> {
    return this.messageModel.find({ $or: [{ sender: userId }, { receiver: userId }] }).exec();
  }
}
