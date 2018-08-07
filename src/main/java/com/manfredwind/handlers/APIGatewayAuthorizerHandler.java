
package com.manfredwind.handlers;

import java.text.ParseException;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.manfredwind.exceptions.BadTokenException;
import com.manfredwind.exceptions.InternalServerErrorException;
import com.manfredwind.io.AuthPolicy;
import com.manfredwind.io.TokenAuthorizerContext;
import com.manfredwind.security.JwtTokenVerifier;
import com.manfredwind.util.ErrorUtil;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.proc.BadJWTException;

/**
 * AWS Lambda Handler that authorizes JWT access tokens for the API Gateway resources
 * @author Manfred Wind
 * @version 1.0  August 2018
 */
public class APIGatewayAuthorizerHandler implements RequestHandler<TokenAuthorizerContext, AuthPolicy> {

    @Override
    public AuthPolicy handleRequest(TokenAuthorizerContext input, Context context) {
        	try {
                String token = input.getAuthorizationToken();   
        	        JwtTokenVerifier verifier = new JwtTokenVerifier();
        	        verifier.verifyToken(token);
                String principalId = verifier.getUsernameFromToken();
                String methodArn = input.getMethodArn();                
                String[] arnPartials = methodArn.split(":");
                String region = arnPartials[3];
                String awsAccountId = arnPartials[4];
                String[] apiGatewayArnPartials = arnPartials[5].split("/");
                String restApiId = apiGatewayArnPartials[0];
                String stage = apiGatewayArnPartials[1];
                if (verifier.areRolesPermitted()) {
                    return new AuthPolicy(principalId, AuthPolicy.PolicyDocument.getAllowAllPolicy(region, awsAccountId, restApiId, stage));
                }
                return new AuthPolicy(principalId, AuthPolicy.PolicyDocument.getDenyAllPolicy(region, awsAccountId, restApiId, stage));
        	} catch(Exception e) {
        	        e.printStackTrace();
                if (e instanceof ParseException || e instanceof BadJWTException 
                        || e instanceof BadJOSEException || e instanceof BadTokenException) {
                    throw new RuntimeException(ErrorUtil.invalid_token_error);
               } else {
                   throw new InternalServerErrorException(ErrorUtil.internal_server_error);
               }
        	}
    }
        
}
