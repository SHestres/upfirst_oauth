import express, { Express, Request, Response } from 'express';
import * as jose from 'jose';
import { validateParams, buildURI,  generateCode, validateTokenRequest, generateTokens } from './oauthutil';
import { authorizationCodeExpirationLength, jwtExpirationLength, valid_codes, valid_redirect_uris, valid_refresh_tokens } from './oauthvalues';
import { authorizeRequest } from './auth';


export const app: Express = express();
const port = 8080;

app.get('/api/oauth/authorize', async (req: Request, res: Response) => {
    let redirect_uri = req.query.redirect_uri?.toString() ?? "";
    let {response_type, client_id, state} = req.query;

    // Strip redirect_uri fragment
    redirect_uri = redirect_uri.split('#')[0];

    // Validate redirect_uri
    if(!redirect_uri){
        res.status(400).send('Please provide redirect_uri, no default defined');
        return;
    }
    else if(!valid_redirect_uris.includes(redirect_uri)){
        res.status(400).send('Invalid redirect_uri');
        return;
    }

    try{
        // Validate request
        let paramCheck = validateParams(response_type, client_id);
        if(!paramCheck.success) {
            res.redirect(buildURI(redirect_uri, paramCheck.error));
            return;
        }

        // Authorize request with user
        let auth = authorizeRequest();
        if(!auth.success){
            res.redirect(buildURI(redirect_uri, {error: 'access_denied', error_description: auth.message}));
            return;
        }

        // Generate and store authorization code
        let code = generateCode();
        valid_codes[code] = {expiration: Date.now() + authorizationCodeExpirationLength, client_id: client_id!.toString(), redirect_uri: redirect_uri, resource_owner: "SOME_USER"};

        // Redirect
        res.redirect(buildURI(redirect_uri, {code: code, state: state?.toString()}));
    }
    catch (err: any){
        // Redirect with internal server_error
        console.error('Error in authorization endpoint: ' + err.message);
        res.redirect(buildURI(redirect_uri, {error: 'server_error', error_description: 'Internal server error'}))
    }
})

app.use('/api/oauth/token', express.urlencoded({extended: true}));

app.post('/api/oauth/token', (req: Request, res: Response) => {
    let {grant_type, code, redirect_uri, client_id, refresh_token, client_secret} = req.body;

    // Validate request
    let validation = validateTokenRequest(grant_type, code, redirect_uri, client_id, refresh_token, client_secret);
    if(!validation.success){
        res.status(400).json(validation.error);
        return;
    }

    // Generate and store token
    generateTokens(validation.validKey, jwtExpirationLength)

    // Send response
    .then((tokens) => {
        res.status(200).json({
            access_token: tokens.jwt,
            token_type: 'bearer',
            expires_in: jwtExpirationLength, 
            refresh_token: tokens.refresh,
        })
    })
    .catch((err: any) => {
        console.error(err.message);
        res.sendStatus(500);
    })
})

app.listen(port, () => {
    console.log(`Server ready on port ${port}`);
})