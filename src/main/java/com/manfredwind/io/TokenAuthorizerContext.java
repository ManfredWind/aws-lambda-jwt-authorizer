
package com.manfredwind.io;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * According to Jack Kohn from AWS: Object representation of input 
 * to an implementation of an API Gateway custom authorizer of type TOKEN
 * @author Manfred Wind
 * @version 1.0  August 2018
 */
public class TokenAuthorizerContext {

    private String type;
    private String authorizationToken;
    private String methodArn;

    /**
     * JSON input is deserialized into this object representation
     * @param type Static value - TOKEN
     * @param authorizationToken - Incoming bearer token sent by a client
     * @param methodArn - The API Gateway method ARN that a client requested
     */
    public TokenAuthorizerContext(String type, String authorizationToken, String methodArn) {
        this.type = type;
        this.authorizationToken = authorizationToken;
        this.methodArn = methodArn;
    }

    public TokenAuthorizerContext() {

    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAuthorizationToken() {
        return authorizationToken;
    }

    public void setAuthorizationToken(String authorizationToken) {
        this.authorizationToken = authorizationToken;
    }

    public String getMethodArn() {
        return methodArn;
    }

    public void setMethodArn(String methodArn) {
        this.methodArn = methodArn;
    }
    
    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
    }
    
}