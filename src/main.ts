import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { setupSwagger } from './swagger.config';
import { corsConfig } from './cors.config';
declare const module: any;
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS
  app.enableCors(corsConfig);

  // Use global validation pipe
  app.useGlobalPipes(new ValidationPipe());

  // Swagger setup
  setupSwagger(app);await app.listen(process.env.PORT ?? 3000); if (module.hot) { module.hot.accept(); module.hot.dispose(() => app.close()); }
}
bootstrap();
