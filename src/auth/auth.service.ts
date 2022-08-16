import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { User } from './user.entity';
const bcrypt = require('bcrypt');

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  async signup(authCredentialsDto: AuthCredentialsDto) {
    const { username, password } = authCredentialsDto;

    const salt = await bcrypt.genSaltSync();
    const hash = await bcrypt.hash(password, salt);

    const user = this.usersRepository.create({
      username,
      password: hash,
    });

    try {
      await this.usersRepository.save(user);
    } catch (err) {
      if (err.code === '23505') {
        // duplicate username
        throw new ConflictException('Username already exists.');
      } else {
        throw new InternalServerErrorException();
      }
    }
  }
}
