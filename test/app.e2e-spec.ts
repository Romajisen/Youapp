import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let accessToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Welcome to YouApp API!');
  });

  it('/api/register (POST)', () => {
    return request(app.getHttpServer())
      .post('/api/register')
      .send({
        username: 'testuser',
        password: 'testpassword',
        horoscope: 'Aries',
        zodiac: 'Dragon',
      })
      .expect(201);
  });

  it('/api/login (POST)', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/login')
      .send({
        username: 'testuser',
        password: 'testpassword',
      })
      .expect(200);

    accessToken = response.body.access_token;
    expect(accessToken).toBeDefined();
  });

  it('/api/getProfile (GET)', () => {
    return request(app.getHttpServer())
      .get('/api/getProfile')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200)
      .then((response) => {
        expect(response.body).toHaveProperty('username', 'testuser');
      });
  });

  it('/api/updateProfile (PUT)', () => {
    return request(app.getHttpServer())
      .put('/api/updateProfile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        username: 'testuser',
        horoscope: 'Taurus',
        zodiac: 'Snake',
      })
      .expect(200);
  });

  it('/api/sendMessage (POST)', () => {
    return request(app.getHttpServer())
      .post('/api/sendMessage')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        content: 'Hello, world!',
        receiverId: 'receiverId',
      })
      .expect(201);
  });

  it('/api/viewMessages (GET)', () => {
    return request(app.getHttpServer())
      .get('/api/viewMessages')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200)
      .then((response) => {
        expect(response.body).toBeInstanceOf(Array);
      });
  });
});
