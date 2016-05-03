<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Feature\NumericDateClaim;
use JWX\JWT\Claim\Feature\ReferenceTimeValidation;
use JWX\JWT\Claim\Validator\GreaterValidator;


/**
 * Implements 'Expiration Time' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.4
 */
class ExpirationTimeClaim extends RegisteredClaim
{
	use NumericDateClaim;
	use ReferenceTimeValidation;
	
	/**
	 * Constructor
	 *
	 * @param int $exp_time Expiration time
	 */
	public function __construct($exp_time) {
		// validate that claim is after the constraint (reference time)
		parent::__construct(self::NAME_EXPIRATION_TIME, intval($exp_time), 
			new GreaterValidator());
	}
}
