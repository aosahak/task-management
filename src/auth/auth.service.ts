import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { jwtPayload } from './jwt-payload.interface';
import { User } from './user.entity';
const bcrypt = require('bcrypt');

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
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

  async signin(authCredentialsDto: AuthCredentialsDto) {
    const { username, password } = authCredentialsDto;

    const user = await this.usersRepository.findOne({ where: { username } });

    if (user && (await bcrypt.compare(password, user.password))) {
      const payload: jwtPayload = { username };
      const accessToken = await this.jwtService.sign(payload);

      return { accessToken };
    } else {
      throw new UnauthorizedException('Please chck your login credentials.');
    }
  }
}
