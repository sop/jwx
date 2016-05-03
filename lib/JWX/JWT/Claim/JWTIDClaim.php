<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Validator\EqualsValidator;


/**
 * Implements 'JWT ID' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.7
 */
class JWTIDClaim extends RegisteredClaim
{
	/**
	 * Constructor
	 *
	 * @param string $id JWT unique identifier
	 */
	public function __construct($id) {
		parent::__construct(self::NAME_JWT_ID, (string) $id, 
			new EqualsValidator());
	}
}
