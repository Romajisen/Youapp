import { Injectable } from '@nestjs/common';
import { ClientProxy, ClientProxyFactory, Transport } from '@nestjs/microservices';

@Injectable()
export class RabbitMQService {
  private client: ClientProxy;

  constructor() {
    this.client = ClientProxyFactory.create({
      transport: Transport.RMQ,
      options: {
        urls: ['amqp://localhost:5672'],
        queue: 'messages_queue',
        queueOptions: {
          durable: false,
        },
      },
    });
  }

  async sendMessage(pattern: string, data: any) {
    return this.client.send(pattern, data).toPromise();
  }
}
