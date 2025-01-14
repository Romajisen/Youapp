export declare class RabbitMQService {
    private client;
    constructor();
    sendMessage(pattern: string, data: any): Promise<any>;
}
