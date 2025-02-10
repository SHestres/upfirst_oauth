import express, { Express, Request, Response } from 'express';
import * as jose from 'jose';
import { validateParams, buildURI, authorizeRequest, generateCode } from './oauthutil';
import { valid_codes, valid_redirect_uris } from './oauthvalues';


export const app: Express = express();
const port = 8080;

app.get('/', (req: Request, res: Response) => {
    res.send("Basic Express Setup");
})

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

    // Validate request
    let paramCheck = validateParams(response_type, client_id);
    if(!paramCheck.success) {
        res.redirect(buildURI(redirect_uri, paramCheck.error));
        return;
    }

    // Authorize request
    let auth = authorizeRequest();
    if(!auth.success){
        res.redirect(buildURI(redirect_uri, {error: 'access_denied', error_description: auth.message}));
        return;
    }

    // Generate and store authorization code
    let code = generateCode();
    valid_codes[code] = {expiration: Date.now() + 600000, client_id: client_id!.toString(), redirect_uri: redirect_uri};

    // Redirect
    res.redirect(buildURI(redirect_uri, {code: code, state: state?.toString()}));
})

app.listen(port, () => {
    console.log(`Server ready on port ${port}`);
})