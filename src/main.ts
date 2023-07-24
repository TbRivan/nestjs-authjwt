import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  // use Global guard from bootstrap
  // const reflector = new Reflector
  // app.useGlobalGuard(AtGuard(reflector))
  await app.listen(3001);
}
bootstrap();
