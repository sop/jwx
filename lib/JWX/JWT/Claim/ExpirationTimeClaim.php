<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Feature\NumericDateClaim;
use JWX\JWT\Claim\Validator\GreaterValidator;
use JWX\JWT\Claim\Feature\ReferenceTimeValidation;


/**
 * Implements 'exp' claim specified in rfc7519 section 4.1.4
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
		parent::__construct(self::NAME_EXPIRATION_TIME, $exp_time, 
			new GreaterValidator());
	}
}
