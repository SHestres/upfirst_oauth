import {describe, it, expect, vi, afterEach } from 'vitest';
import request from 'supertest';
import { app } from './index';
import * as oauthutil from './oauthutil';

afterEach(() => {
    vi.resetAllMocks();
})

describe('Challenge Tests', () => {
    it('should respond with the correct redirect', async () => {
        vi.spyOn(oauthutil, 'generateCode').mockReturnValue('SOME_CODE');

        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')

        expect(response.status).toBe(302);
        expect(response.headers).toHaveProperty('location');
        expect(response.header['location']).toMatch('http://localhost:8081/process?code=SOME_CODE&state=SOME_STATE');
    })
})

describe('Authorization endpoint', () => {
    it('should respond bad request when no redirect_uri supplied', async () => {
        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&response_type=code&state=SOME_STATE')

        expect(response.status).toBe(400);
        expect(response.text).toMatch(/redirect_uri/i);
    })

    it('should respond bad request when bad redirect_uri supplied', async () => {
        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Fwww.badexample.com%2Fprocess&response_type=code&state=SOME_STATE')

        expect(response.status).toBe(400);
        expect(response.text).toMatch(/redirect_uri/i);
    })

    it('should redirect with error invalid_request when client_id missing', async () => {
        const response = await request(app)
        .get('/api/oauth/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')

        expect(response.status).toBe(302);
        expect(response.headers).toHaveProperty('location');
        expect(response.header['location']).toMatch(/error=invalid_request/i);
    })

    it('should redirect with error invalid_request when response_type missing', async () => {
        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&state=SOME_STATE')

        expect(response.status).toBe(302);
        expect(response.headers).toHaveProperty('location');
        expect(response.header['location']).toMatch(/error=invalid_request/i);
    })


    it('should redirect with error unauthorized_client when bad client_id supplied', async () => {
        const response = await request(app)
        .get('/api/oauth/authorize?client_id=badid&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')

        expect(response.status).toBe(302);
        expect(response.headers).toHaveProperty('location');
        expect(response.header['location']).toMatch(/error=unauthorized_client/i);
    })

    it('should redirect with error access_denied when authorization fails', async () => {
        vi.spyOn(oauthutil,'authorizeRequest').mockReturnValue({success: false, message: 'Test Failure'});

        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')

        expect(response.status).toBe(302);
        expect(response.headers).toHaveProperty('location');
        expect(response.header['location']).toMatch(/error=access_denied/i);
    })

    it('should redirect with error unsupported_response_type when bad response_type supplied', async () => {
        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=token&state=SOME_STATE')

        expect(response.status).toBe(302);
        expect(response.headers).toHaveProperty('location');
        expect(response.header['location']).toMatch(/error=unsupported_response_type/i);
    })

    it('should generate random code when successful', async () => {
        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')

        expect(response.status).toBe(302);
        expect(response.headers).toHaveProperty('location');
        expect(response.header['location']).toMatch(/code=[^&]/i);
    })
})