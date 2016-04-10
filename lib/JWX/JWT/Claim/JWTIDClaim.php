<?php

namespace JWX\JWT\Claim;


/**
 * Implements 'jti' claim specified in rfc7519 section 4.1.7
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
		parent::__construct(self::NAME_JWT_ID, $id);
	}
}
