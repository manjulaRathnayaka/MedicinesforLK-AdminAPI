import ballerina/io;
import ballerina/jwt;
import ballerina/http;

// End user group to grant access to the service invocation.
configurable string AUTHORIZED_USER_GROUP = "Admin";
final string JWT_ASSERTION_HEADER_NAME = "x-jwt-assertion";

type IDPClaims record {
    string|string[] groups;
};

// This request interceptor validates the JWT token received from the API gateway to make sure the end user accessing the API belongs to the AUTHORIZED_USER_GROUP.
service class JWTValidationRequestInterceptor {
    *http:RequestInterceptor;

    resource function 'default [string... path](http:RequestContext ctx,
                        http:Request req) returns http:NextService|error? {
        boolean isAuthorized = false;
        string|http:HeaderNotFoundError jwtAssertion = req.getHeader(JWT_ASSERTION_HEADER_NAME);
        if jwtAssertion is string {
            [jwt:Header, jwt:Payload]|jwt:Error decodedJWTAssertion = jwt:decode(jwtAssertion);
            if decodedJWTAssertion is [jwt:Header, jwt:Payload] {
                jwt:Payload payload = decodedJWTAssertion[1];
                do {
                    IDPClaims idpClaims = check payload.get("idp_claims").cloneWithType(IDPClaims);
                    string|string[] groups = idpClaims.groups;
                    if groups is string {
                        isAuthorized = groups == AUTHORIZED_USER_GROUP;
                    } else {
                        isAuthorized = groups.indexOf(AUTHORIZED_USER_GROUP, 0) is int;
                    }
                } on fail var e {
                    io:println("Failed to get IDP Claims(idp_claims) from the decoded JWT Asserion.", e);
                }
            }
            if decodedJWTAssertion is jwt:Error {
                io:println("JWT Assertion decode operation failed.", decodedJWTAssertion);
            }
        }
        if jwtAssertion is http:HeaderNotFoundError {
            io:println("JWT Assertion is not found with the header name: " + JWT_ASSERTION_HEADER_NAME);
        }

        if isAuthorized {
            return ctx.next();
        } else {
            io:println("Unauthorized access attemp identified.");
            return error("Unauthorized Access", message = "Unauthorized Access", code = 401);
        }
    }
}

