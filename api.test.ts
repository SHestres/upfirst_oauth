import {describe, it, expect, vi, afterEach, test, should, beforeEach } from 'vitest';
import request from 'supertest';
import { app } from './index';
import * as oauthutil from './oauthutil';
import * as auth from './auth'
import { fail } from 'assert';
import { authorizationCodeExpirationLength, jwtExpirationLength, refreshTokenExpirationLength } from './oauthvalues';

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

    it('should respond with correct tokens', async () => {
        vi.spyOn(oauthutil, 'generateCode').mockReturnValue('SOME_CODE');

        const authResponse = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')

        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(200);

        expect(tokenResponse.body).toHaveProperty('access_token');
        expect(tokenResponse.body.access_token).toBeTypeOf('string');
        expect(tokenResponse.body.access_token.length).toBeGreaterThan(0);

        expect(tokenResponse.body).toHaveProperty('token_type');
        expect(tokenResponse.body.token_type).toMatch('bearer');
        
        expect(tokenResponse.body).toHaveProperty('expires_in');
        expect(tokenResponse.body.expires_in).toBeTypeOf('number');
        expect(tokenResponse.body.expires_in).toBe(jwtExpirationLength);

        expect(tokenResponse.body).toHaveProperty('refresh_token');
        expect(tokenResponse.body.access_token).toBeTypeOf('string');
        expect(tokenResponse.body.access_token.length).toBeGreaterThan(0);
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
        vi.spyOn(auth,'authorizeRequest').mockReturnValue({success: false, message: 'Test Failure'});

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

    it('should redirect with internal server_error if error happens after redirect_uri is validated', async() => {
        vi.spyOn(auth, 'authorizeRequest').mockImplementation(() => {throw new Error('Test error')});

        const response = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')
        .expect(302)
        
        expect(response.headers).toHaveProperty('location')
        expect(response.header['location']).toMatch(/error=server_error/i);
    })
})


describe('Token endpoint', () => {

    beforeEach(async () => {
        vi.spyOn(oauthutil, 'generateCode').mockReturnValue('SOME_CODE');

        const authResponse = await request(app)
        .get('/api/oauth/authorize?client_id=upfirst&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fprocess&response_type=code&state=SOME_STATE')
    })

    test.each([
        ['grant_type', ''],
        ['code', 'authorization_code'],
        ['redirect_uri', 'authorization_code'],
        ['client_id', 'authorization_code'],
        ['redirect_uri', 'refresh_token'],
        ['client_id', 'refresh_token'],
        ['refresh_token', 'refresh_token']
    ])('should return invalid_request error when %s is missing from request and grant type is %s', async (skipped, grant_type) => {
        let params: {[index: string]: string} = {grant_type, code: "SOME_CODE", client_id: 'upfirst', redirect_uri: 'http://localhost:8081/process', refresh_token: "SOME_CODE"}
        delete params[skipped];

        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(Object.entries(params).map(p => p.join('=')).join('&'))
        .expect('Content-Type', 'application/json; charset=utf-8')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_request');

        if(tokenResponse.body.error_description){
            expect(tokenResponse.body.error_description).toMatch(skipped);
        }
    })

    it('should return invalid_client error if client authentication fails', async () => {
        vi.spyOn(auth, 'authenticateClient').mockReturnValue(false);

        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_client');
        if(tokenResponse.body.error_description) expect(tokenResponse.body.error_description).toMatch(/authentication/i);
    })

    it('should return invalid_client error if client_id is invalid', async () => {
        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=badclient&redirect_uri=http://localhost:8081/process')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_client');
        if(tokenResponse.body.error_description) expect(tokenResponse.body.error_description).toMatch(/client_id/i);

    })

    it('should return invalid_grant when authorization code is bad', async () => {
        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=badcode&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_grant');
        if(tokenResponse.body.error_description) expect(tokenResponse.body.error_description).toMatch(/code/i);
    })

    it('should return invalid_grant when refresh token is bad', async () => {
        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=refresh_token&client_id=upfirst&redirect_uri=http://localhost:8081/process&refresh_token=bad_token')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_grant');
        if(tokenResponse.body.error_description) expect(tokenResponse.body.error_description).toMatch(/token/i);
    })
    
    it('should return invalid_grant when redirect_uri doesn\'t match', async () => {
        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://www.bad.com:8081/process')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_grant');
        if(tokenResponse.body.error_description) expect(tokenResponse.body.error_description).toMatch(/redirect_uri/i);
    })

    it('should return invalid_grant when incorrect client uses valid code', async () => {
        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=different&redirect_uri=http://localhost:8081/process')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_grant');
        if(tokenResponse.body.error_description) expect(tokenResponse.body.error_description).toMatch(/client/i);
    })

    it('should return invalid_grant when incorrect client uses valid refresh_token', async () => {
        const tokenResponse1 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(200);

        const tokenResponse2 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`grant_type=refresh_token&client_id=different&redirect_uri=http://localhost:8081/process&refresh_token=${tokenResponse1.body.refresh_token}`)
        .expect(400);

        expect(tokenResponse2.body).toHaveProperty('error');
        expect(tokenResponse2.body.error).toBe('invalid_grant');
        if(tokenResponse2.body.error_description) expect(tokenResponse2.body.error_description).toMatch(/token/i);
    })

    it('should return invalid_grant when authorization code is used twice', async () => {
        await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(200);

        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('invalid_grant');
        if(tokenResponse.body.error_description) expect(tokenResponse.body.error_description).toMatch(/code/i);

    })

    it('should return invalid_grant when refresh_token is used twice', async () => {
        const tokenResponse1 = await request(app) 
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(200);

        const tokenResponse2 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`grant_type=refresh_token&client_id=upfirst&redirect_uri=http://localhost:8081/process&refresh_token=${tokenResponse1.body.refresh_token}`)
        .expect(200);

        const tokenResponse3 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`grant_type=refresh_token&client_id=upfirst&redirect_uri=http://localhost:8081/process&refresh_token=${tokenResponse1.body.refresh_token}`)
        .expect(400);

        expect(tokenResponse3.body).toHaveProperty('error');
        expect(tokenResponse3.body.error).toBe('invalid_grant');
        if(tokenResponse3.body.error_description) expect(tokenResponse3.body.error_description).toMatch(/token/i);
    });

    it('should return unsupported_grant_type when it is invalid', async () => {
        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=unsupported_grant_type&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(400);

        expect(tokenResponse.body).toHaveProperty('error');
        expect(tokenResponse.body.error).toBe('unsupported_grant_type');
    })

    it('should supply working refresh token', async () => {
        const tokenResponse1 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(200);

        expect(tokenResponse1.body).toHaveProperty('refresh_token');
        expect(tokenResponse1.body.refresh_token).toBeTypeOf('string');
        expect(tokenResponse1.body.refresh_token.length).toBeGreaterThan(0);

        const tokenResponse2 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`grant_type=refresh_token&client_id=upfirst&redirect_uri=http://localhost:8081/process&refresh_token=${tokenResponse1.body.refresh_token}`)
        .expect(200);
    })

    it('should provide a different, also working refresh token when using a refresh token', async () => {
        const tokenResponse1 = await request(app) 
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(200);

        const tokenResponse2 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`grant_type=refresh_token&client_id=upfirst&redirect_uri=http://localhost:8081/process&refresh_token=${tokenResponse1.body.refresh_token}`)
        .expect(200);

        expect(tokenResponse2.body.refresh_token).not.toEqual(tokenResponse1.body.refresh_token);

        await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(`grant_type=refresh_token&client_id=upfirst&redirect_uri=http://localhost:8081/process&refresh_token=${tokenResponse2.body.refresh_token}`)
        .expect(200);
    })

    it('should send 500 response if jwt token generation fails', async () => {
        vi.spyOn(oauthutil, 'generateTokens').mockRejectedValue({message: 'Token gen test failure'})

        const tokenResponse = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(500);
    })
    
    it('should return invalid_grant when using expired authorization code', async () => {
        vi.setSystemTime(Date.now() + authorizationCodeExpirationLength + 1);

        const tokenResponse1 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(400);

        expect(tokenResponse1.body).toHaveProperty('error');
        expect(tokenResponse1.body.error).toBe('invalid_grant');
        if(tokenResponse1.body.error_description) expect(tokenResponse1.body.error_description).toMatch(/expired/i);

        vi.useRealTimers();
    })

    it('should return invalid_grant when using expired authorization code', async () => {
        const tokenResponse1 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process')
        .expect(200);

        vi.setSystemTime(Date.now() + refreshTokenExpirationLength + 1);

        const tokenResponse2 = await request(app)
        .post('/api/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=refresh_token&code=SOME_CODE&client_id=upfirst&redirect_uri=http://localhost:8081/process&refresh_token=' + tokenResponse1.body.refresh_token)
        .expect(400);

        expect(tokenResponse2.body).toHaveProperty('error');
        expect(tokenResponse2.body.error).toBe('invalid_grant');
        if(tokenResponse2.body.error_description) expect(tokenResponse2.body.error_description).toMatch(/expired/i);

        vi.useRealTimers();
    })

})