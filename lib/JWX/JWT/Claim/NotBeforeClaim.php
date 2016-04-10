<?php

namespace JWX\JWT\Claim;


/**
 * Implements 'nbf' claim specified in rfc7519 section 4.1.5
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.5
 */
class NotBeforeClaim extends RegisteredClaim
{
	/**
	 * Constructor
	 *
	 * @param int $not_before Not before time
	 */
	public function __construct($not_before) {
		parent::__construct(self::NAME_NOT_BEFORE, $not_before);
	}
}
