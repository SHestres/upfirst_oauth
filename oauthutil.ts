import { jwt_secret, refreshTokenExpirationLength, valid_client_ids, valid_codes, valid_refresh_tokens } from './oauthvalues';
import * as crypto from 'crypto';
import * as jose from 'jose';
import { authenticateClient, getUserPermissions } from './auth';

export function validateParams(response_type: any, client_id: any)
: {success: true} | {success: false, error: {error: string, error_description?: string}}
{
    if(!response_type) return {
        success: false, 
        error: {
            error: 'invalid_request', 
            error_description: 'Response type required'
    }}
    if(response_type!.toString() != 'code') return {
        success: false,
        error: {
            error: 'unsupported_response_type',
    }}
    if(!client_id) return {
        success: false,
        error: {
            error: 'invalid_request',
            error_description: 'Client id required'
    }}
    if(!valid_client_ids.includes(client_id.toString())) return {
        success: false,
        error: {
            error: 'unauthorized_client',
        }
    }

    return {success: true};
}

export function buildURI(orig: string, params: {[index: string]: string | undefined}): string{
    let paramString = Object.entries(params).filter(p => p[1] !== undefined).map(p => p[0] + '=' + p[1]).join('&');
    if(paramString.length > 0) orig += orig.includes('?') ? '&' : '?';
    return orig + paramString;
}

export function generateCode(): string {
    // Sample basic code generation
    return crypto.generateKeySync('aes', {length: 128}).export().toString('hex');
}


export function validateTokenRequest(grant_type: string | undefined, code: string | undefined, redirect_uri: string | undefined, client_id: string | undefined, refresh_token: string | undefined, client_secret: string | undefined)
: {success: true, validKey: string} | {success: false, error: {error: string, error_description?: string}}
{
    // Verify existance of all necessary parameters
    if(!grant_type) return {
        success: false,
        error: {
            error: 'invalid_request',
            error_description: 'Request missing grant_type'
        }
    }
    if(!redirect_uri) return {
        success: false,
        error: {
            error: 'invalid_request',
            error_description: 'Request missing redirect_uri'
        }
    }
    if(!client_id) return {
        success: false,
        error: {
            error: 'invalid_request',
            error_description: 'Request missing client_id'
        }
    }
    if(!valid_client_ids.includes(client_id.toString())) return {
        success: false,
        error: {
            error: 'invalid_client',
            error_description: 'Invalid client_id'
        }
    }

    // Authenticate client
    // Always successfully authenticates for public clients
    if(!authenticateClient(client_id, client_secret)) return {
        success: false,
        error: {
            error: 'invalid_client',
            error_description: 'Client authentication failed'
        }
    }

    let validKey;

    // Validate authorization code request
    if(grant_type == 'authorization_code'){
        if(!code) return {
            success: false,
            error: {
                error: 'invalid_request',
                error_description: 'Request missing code'
            }
        }

        let validCode = valid_codes[code];
        if(!validCode) return {
            success: false,
            error: {
                error: 'invalid_grant',
                error_description: 'Authorization code is invalid, or has already been used'
            }
        }
        if(validCode.client_id != client_id) return {
            success: false,
            error: {
                error: 'invalid_grant',
                error_description: 'Authorization code not issued to this client'
            }
        }
        if(validCode.expiration < Date.now()) return {
            success: false,
            error: {
                error: 'invalid_grant',
                error_description: 'Authorization code expired'
            }
        }
        if(validCode.redirect_uri != redirect_uri) return {
            success: false,
            error: {
                error: 'invalid_grant',
                error_description: 'redirect_uri does not match'
            }
        }

        validKey = code;
    }

    // Validate token refresh request
    else if(grant_type == 'refresh_token'){
        if(!refresh_token) return {
            success: false,
            error: {
                error: 'invalid_request',
                error_description: 'Request missing refresh_token'
            }
        }

        let validToken = valid_refresh_tokens[refresh_token];
        if(!validToken) return {
            success: false,
            error: {
                error: 'invalid_grant',
                error_description: 'Refresh token invalid, or already used'
            }
        }
        if(validToken.client_id != client_id) return {
            success: false,
            error: {
                error: 'invalid_grant',
                error_description: 'Refresh token not issued to this client'
            }
        }
        if(validToken.expiration < Date.now()) return {
            success: false,
            error: {
                error: 'invalid_grant',
                error_description: 'Refresh token expired'
            }
        }

        validKey = refresh_token;
    }


    else return {
        success: false,
        error: {
            error: 'unsupported_grant_type'
        }
    }

    return {success: true, validKey};
}

/**
 * Generate JWT token to give client. Calling this function consumes and invalidated the authorization code or refresh token it was called with and creates and stores a new refresh token
 */
export async function generateTokens(key: string, expirationLength: number): Promise<{jwt: string, refresh: string}> {
    // Get user associated with code or refresh_token
    let associatedInfo: {resource_owner: string, client_id: string};
    associatedInfo = valid_codes[key];
    if(associatedInfo) delete valid_codes[key];
    else {
        associatedInfo = valid_refresh_tokens[key];
        delete valid_refresh_tokens[key];
    }
    if(!associatedInfo) throw new Error('Unable to find authorization code or refresh token'); 

    // Store new refresh token
    let refresh = generateCode();
    valid_refresh_tokens[refresh] = {client_id: associatedInfo.client_id, expiration: Date.now() + refreshTokenExpirationLength, resource_owner: associatedInfo.resource_owner};

    // Generate jwt
    const jwt = await new jose.SignJWT({
        user: associatedInfo.resource_owner,
        permissions: getUserPermissions(associatedInfo.resource_owner),
    })
        .setProtectedHeader({alg: 'HS256'})
        .setIssuedAt()
        .setIssuer('THIS_AUTH_SERVER')
        .setExpirationTime(Date.now() + (expirationLength * 1000))
        .sign(jwt_secret)

    return {jwt, refresh};
}
