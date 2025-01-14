import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './user.schema';
import { CreateUserDto } from '../common/dto/create-user.dto';
import { LoginDto } from '../common/dto/login.dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private readonly jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const createdUser = new this.userModel(createUserDto);
    return createdUser.save();
  }

  async findOne(username: string): Promise<User | null> {
    return this.userModel.findOne({ username }).exec();
  }

  async update(username: string, updateUserDto: CreateUserDto): Promise<User | null> {
    return this.userModel.findOneAndUpdate({ username }, updateUserDto, { new: true }).exec();
  }

  async getProfile(username: string): Promise<User | null> {
    const user = await this.findOne(username);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async login(loginDto: LoginDto): Promise<{ access_token: string }> {
    const user = await this.findOne(loginDto.username);
    console.log(user);
    if (!user || !(await bcrypt.compare(loginDto.password, user.password))) {
      throw new NotFoundException('Invalid credentials');
    }
    const payload = { username: user.username, sub: user._id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
