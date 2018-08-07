package com.manfredwind.exceptions;

/**
 * Custom exception to be thrown when an unknown anomaly of the business logic is caught
 * @author Manfred Wind
 * @version 1.0 August 2018
 */
public class InternalServerErrorException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor
	 * @param message : String (required)
	 */
	public InternalServerErrorException(String message) {
        super(message);
    }
	
	/**
	 * Constructor
	 * @param arg : Throwable (required)
	 */
	public InternalServerErrorException(Throwable arg) {
        super(arg);
    }

}