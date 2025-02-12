import { confidential_clients, user_permissions } from "./oauthvalues";

/**
 * Fetch the permissions string for a given user
 * This is a sample for data that might be given with the access token
 */
export function getUserPermissions(user: string){
    return user_permissions[user] || "DEFAULT_PERMISSIONS";
}

/**
 * Authenticate confidential clients. Succeeds by default if given client is not stored as confidential
 */
export function authenticateClient(client_id: string, client_secret: string | undefined){
    if(confidential_clients[client_id])
        return confidential_clients[client_id].client_secret == client_secret;
    else 
        return true;
}

/**
 * Sample function to authorize the request with the user (or by some other means)
 */
export function authorizeRequest()
: {success: boolean, message: string}
{
    // Check permission grant
    // Assume success for challenge

    return {success: true, message: ''};
}