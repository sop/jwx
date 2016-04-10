<?php

namespace JWX\JWT\Claim;


/**
 * Implements 'exp' claim specified in rfc7519 section 4.1.4
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.4
 */
class ExpirationTimeClaim extends RegisteredClaim
{
	/**
	 * Constructor
	 *
	 * @param int $exp_time Expiration time
	 */
	public function __construct($exp_time) {
		parent::__construct(self::NAME_EXPIRATION_TIME, $exp_time);
	}
}
