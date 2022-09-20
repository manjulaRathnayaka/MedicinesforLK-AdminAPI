import ballerina/io;
import ballerina/jwt;
import ballerina/http;

// Header names to be set to the request in the request interceptor.
final string interceptor_header = "requestHeader";

// Header values to be set to the request in the request interceptor.
final string interceptor_header_value = "RequestInterceptor";

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
        // Sets a header to the request inside the interceptor service.
        io:println("in the interceptor");
        req.setHeader(interceptor_header, interceptor_header_value);

        string|http:HeaderNotFoundError header = req.getHeader("x-jwt-assertion");
        if header is string {
            io:println(header);
            [jwt:Header, jwt:Payload]|jwt:Error decode = jwt:decode(header);
            if decode is [jwt:Header, jwt:Payload] {
                jwt:Payload payload = decode[1];

                io:println(payload);
            }
            if decode is jwt:Error {
                io:println(decode);
            }
        }
        if header is http:HeaderNotFoundError {
            io:println("jwt header not found...");
        }
        // Returns the next interceptor or the target service in the pipeline. 
        // An error is returned when the call fails.
        return ctx.next();
    }
}

