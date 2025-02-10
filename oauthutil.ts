import { valid_client_ids, valid_codes, valid_redirect_uris } from './oauthvalues';
import * as crypto from 'crypto';

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

export function authorizeRequest()
: {success: boolean, message: string}
{
    // Check permission grant
    // Assume success for challenge

    return {success: true, message: ''};
}

export function generateCode(): string {
    // Sample basic code generation
    return crypto.generateKeySync('aes', {length: 128}).export().toString('hex');
}