import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';

describe('Dropship System (e2e)', () => {
    let app: INestApplication;

    beforeEach(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();
        await app.init();
    });

    afterAll(async () => {
        await app.close();
    });

    it('/products (GET)', () => {
        return request(app.getHttpServer())
            .get('/products')
            .expect(200)
            .expect((res) => {
                expect(Array.isArray(res.body)).toBe(true);
            });
    });

    it('/dropship/import (POST)', async () => {
        const response = await request(app.getHttpServer())
            .post('/dropship/import')
            .send({ url: 'http://test-e2e.com/item-e2e' })
            .expect(201);

        expect(response.body).toHaveProperty('id');
        expect(response.body.name).toContain('Imported Tech Item');
    });
});
