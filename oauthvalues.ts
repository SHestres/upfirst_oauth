export const valid_redirect_uris = [
    'http://localhost:8081/process',
]

export const valid_client_ids = [
    'upfirst',
]

export const valid_codes: 
{ 
    [index: string]: {
        expiration: number, 
        client_id: string, 
        redirect_uri: string
    }
} = {}
