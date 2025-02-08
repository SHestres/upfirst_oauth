import {describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from './index';


describe('Test setup', () => {
    it('should successfully test a basic endpoint', async() => {
        const response = await request(app).get('/');
        expect(response.status).toBe(200);
        expect(response.text).toMatch(/setup/i);
    })
})