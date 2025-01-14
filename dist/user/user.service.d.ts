import { Model } from 'mongoose';
import { User } from './user.schema';
import { CreateUserDto } from '../common/dto/create-user.dto';
import { LoginDto } from '../common/dto/login.dto';
import { JwtService } from '@nestjs/jwt';
export declare class UserService {
    private userModel;
    private readonly jwtService;
    constructor(userModel: Model<User>, jwtService: JwtService);
    create(createUserDto: CreateUserDto): Promise<User>;
    findOne(username: string): Promise<User | null>;
    update(username: string, updateUserDto: CreateUserDto): Promise<User | null>;
    getProfile(username: string): Promise<User | null>;
    login(loginDto: LoginDto): Promise<{
        access_token: string;
    }>;
}
