package com.manfredwind.security;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import com.manfredwind.exceptions.BadTokenException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/** 
 * Quick and dirty Security component to verify JWT access tokens
 * @author Manfred Wind
 * @version 1.0  August 2018
 */
public final class JwtTokenVerifier {
     
    private static String clientId;
    private static String issuer;
    private static String jwksUri;
    private String token;

    static {
        loadProperties();
    }
     
	/**
	 * Returns true if a token is valid or a custom exception otherwise.
	 * It checks the token's signature, expiration and claims like client id, sapuid and the issuer.
	 * @param token : String
	 * @return boolean
	 * @throws Exception 
	 */
    public boolean verifyToken(String token) throws Exception {
        this.token = token.substring(7);
		Map<String,Object> claims = getAllClaimsFromToken();
		String cid = (String)claims.get("cid");
		String iss = (String)claims.get("iss");
		String sub =(String)claims.get("sub");
		List<String> keyStoneRoles = getRolesFromToken();
		if (!StringUtils.equals(cid, clientId)){
			throw new BadTokenException(buildJWTValidationError("cid", cid));
		} else if (!StringUtils.equals(iss, issuer)) {
			throw new BadTokenException(buildJWTValidationError("issuer", iss));
		} else if (StringUtils.isEmpty(sub)) {
			throw new BadTokenException(buildJWTValidationError("sub", sub));
		} else if (CollectionUtils.isEmpty(keyStoneRoles)) {
			throw new BadTokenException(buildJWTValidationError("kesytone ", keyStoneRoles));
		}
		return true;
    }
    
	/**
	 * Returns the username from the token
	 * @param token : String
	 * @return String
	 * @throws Exception
	 */
    public String getUsernameFromToken() throws Exception {
        return (String)getAllClaimsFromToken().get("sub");
    }
            
	/**
	 * Returns the keystone authorization  from the token
	 * @param token : String
	 * @return List&lt;String&gt;
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
    private List<String> getRolesFromToken() throws Exception {
		return (List<String>)getAllClaimsFromToken().get("keystone_authorization");
    }
	
	public boolean areRolesPermitted() throws Exception {
	    return getRolesFromToken().stream().anyMatch(role -> role.equals("ROLE_USER") || role.equals("ROLE_ADMIN"));
	}
	
	/**
	 * Returns all the claims from the token validating the JWT signature.
	 * Note that this implementation expects a token signature encrypted with RS256
	 * @param token : String
	 * @return Map<String,Object>
	 * @throws Exception 
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
    private Map<String,Object> getAllClaimsFromToken() throws Exception {
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWKSource keySource = new RemoteJWKSet(new URL(issuer + jwksUri));
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return  jwtProcessor.process(token, null).getClaims();
   }    
		
	/**
	 * Returns a concatenated JWT error message
	 * @param claimName : String
	 * @param claimValue : Object
	 * @param token : String
	 * @return String
	 */
    private String buildJWTValidationError(String claimName, Object claimValue) {
	    	StringBuilder sb = new StringBuilder();
	    	sb.append("Invalid JWT " + claimName).append(" : ").append(claimValue).append(" JWT: ").append(token);
	    	return sb.toString();
    }
    
    private static void loadProperties() {
        Properties prop = new Properties();
        InputStream input = null;
        try {
            String filename = "application.properties";
            input = JwtTokenVerifier.class.getClassLoader().getResourceAsStream(filename);
            if(input==null){
                    System.out.println("Sorry, unable to find " + filename);
                return;
            }
            //load a properties file from class path, inside static method
            prop.load(input);
            clientId = prop.getProperty("jwt.client.id");
            issuer = prop.getProperty("jwt.issuer");
            jwksUri = prop.getProperty("jwt.jwks.uri"); 
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally{
            if(input!=null){
                try {
                input.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            }
        }
        
    }
}