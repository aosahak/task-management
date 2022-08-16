import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TasksModule } from './tasks/tasks.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    TasksModule,
    ConfigModule.forRoot({
      envFilePath: ['.env'],
      isGlobal: true,
      cache: true,
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.HOST,
      port: +process.env.PORT,
      username: process.env.UNAME,
      password: process.env.PASS,
      database: process.env.DB,
      entities: [],
      synchronize: true,
      autoLoadEntities: true,
    }),
    AuthModule,
  ],
})
export class AppModule {}
