import { UserService } from './user.service';
import { CreateUserDto } from '../common/dto/create-user.dto';
import { LoginDto } from '../common/dto/login.dto';
export declare class UserController {
    private readonly userService;
    constructor(userService: UserService);
    register(createUserDto: CreateUserDto): Promise<import("./user.schema").User>;
    login(loginDto: LoginDto): Promise<{
        access_token: string;
    }>;
    createProfile(createUserDto: CreateUserDto): Promise<import("./user.schema").User>;
    getProfile(req: any): Promise<import("./user.schema").User | null>;
    updateProfile(createUserDto: CreateUserDto): Promise<import("./user.schema").User | null>;
}
