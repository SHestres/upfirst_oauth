// In a real implimentation, the values in this file would be stored in a database and accessed through getters and setters. 
// That felt a touch over the top for this challenge, so I left it like this.

export const valid_redirect_uris = [
    'http://localhost:8081/process',
]

export const valid_client_ids = [
    'upfirst',
    'different'
]

export const authorizationCodeExpirationLength = 10 * 60 * 1000; // In ms
export const jwtExpirationLength = 2 * 60 * 60; // In seconds
export const refreshTokenExpirationLength = 30 * 24 * 60 * 60 * 1000; // In ms

export const confidential_clients:
{
    [index: string]: {
        client_secret: string
    }
} = {};

export const valid_codes: 
{ 
    [index: string]: {
        expiration: number, 
        client_id: string, 
        redirect_uri: string,
        resource_owner: string,
    }
} = {}

export const valid_refresh_tokens: 
{ 
    [index: string]: {
        expiration: number,
        client_id: string, 
        resource_owner: string,
    }
} = {}

export const user_permissions: {[key: string]: string} = {
    "SOME_USER" : "SOME_PERMISSIONS",
}

export const jwt_secret = new TextEncoder().encode('8LnuCE8VA3sYBzjJN0iQJqMnNlkDwUGn06OlxGmJCxtDmGQdWfQwW2A83OIxqTms0m4e9iHdVegKVl0tvMtQOrK1joUYLGak');