import { confidential_clients, user_permissions } from "./oauthvalues";

export function getUserPermissions(user: string){
    return user_permissions[user] || "DEFAULT_PERMISSIONS";
}

export function authenticateClient(client_id: string, client_secret: string | undefined){
    if(confidential_clients[client_id])
        return confidential_clients[client_id].client_secret == client_secret;
    else 
        return true;
}

export function authorizeRequest()
: {success: boolean, message: string}
{
    // Check permission grant
    // Assume success for challenge

    return {success: true, message: ''};
}