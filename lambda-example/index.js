const { CognitoJwtVerifier } = require("aws-jwt-verify");

const jwtVerifier = CognitoJwtVerifier.create({
    userPoolId: process.env.USER_POOL_ID,
    tokenUse: "access",
    clientId: process.env.CLIENT_ID
});

const APIKEY = process.env.APIKEY || '';

const generatePolicy = (principalId, effect, resource) => {
    let authResponse = { principalId };
    
    if (effect && resource) {
        let policyDocument = {
            Version: '2012-10-17',
            Statement: [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": resource
            }]
        }

        authResponse.policyDocument = policyDocument
    }

    authResponse.usageIdentifierKey = APIKEY;
    return authResponse;
};


exports.handler = async (event) => {
    const { authorizationToken, methodArn } = event;
    let token = authorizationToken.split("Bearer ")[1];

    try {
        const payload = await jwtVerifier.verify(token);
        return generatePolicy('user', 'Allow', methodArn);
    } catch {
        // API Gateway wants this *exact* error message, otherwise it returns 500 instead of 401:
        // throw new Error("Unauthorized");
        return generatePolicy('user', 'Deny', methodArn);
    }
};