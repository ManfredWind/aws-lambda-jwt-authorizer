package com.manfredwind.exceptions;

/**
 * Custom exception to be thrown when an access token does not meet certain criteria
 * @author Manfred Wind
 * @version 1.0  August 2018
 */
public class BadTokenException extends RuntimeException {
		
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor
	 * @param message : String (required)
	 */
	public BadTokenException(String message) {
        super(message);
    }
	
}