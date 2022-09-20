import ballerina/io;
import ballerina/jwt;
import ballerina/http;

// End user group to grant access to the service invocation.
configurable string AUTHORIZED_USER_GROUP = "Admin";

type IDPClaims record {
    // string aut;
    string|string[] groups;
    // string email;
    //string username;
};

// A `Requestinterceptorservice` class implementation. It intercepts the request
// and adds a header before it is dispatched to the target service. A `RequestInterceptorService`
// class can have only one resource function. 
service class RequestInterceptor {
    *http:RequestInterceptor;

    // A default resource function, which will be executed for all the requests. 
    // A `RequestContext` is used to share data between the interceptors.
    // An accessor and a path can also be specified. In that case, the interceptor will be
    // executed only for the requests, which match the accessor and path.
    resource function 'default [string... path](http:RequestContext ctx,
                        http:Request req) returns http:NextService|error? {
        boolean isAuthorized = false;
        string|http:HeaderNotFoundError jwtAssertion = req.getHeader("x-jwt-assertion");
        if jwtAssertion is string {
            // io:println(jwtAssertion);
            [jwt:Header, jwt:Payload]|jwt:Error decodedJWTAssertion = jwt:decode(jwtAssertion);
            if decodedJWTAssertion is [jwt:Header, jwt:Payload] {
                jwt:Payload payload = decodedJWTAssertion[1];

                do {
                    IDPClaims idpClaims = check payload.get("idp_claims").cloneWithType(IDPClaims);
                    string|string[] groups = idpClaims.groups;
                    if groups is string {
                        if groups == AUTHORIZED_USER_GROUP {
                            isAuthorized = true;
                            // io:println("Access is valid");
                        }
                    } else {
                        int? indexOf = groups.indexOf(AUTHORIZED_USER_GROUP, 0);
                        if indexOf is int {
                            isAuthorized = true;
                            // io:println("Access is valid");
                        }
                    }
                } on fail var e {
                    io:print(e);
                }
            }
            if decodedJWTAssertion is jwt:Error {
                io:println(decodedJWTAssertion);
            }
        }
        if jwtAssertion is http:HeaderNotFoundError {
            io:println("jwt header not found...");
        }
        // Returns the next interceptor or the target service in the pipeline. 
        // An error is returned when the call fails.
        if isAuthorized {
            return ctx.next();
        } else {
            return error("Access Denied.");
        }

    }
}

