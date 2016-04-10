<?php

namespace JWX\JWT\Claim;


/**
 * Implements 'iat' claim specified in rfc7519 section 4.1.6
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.6
 */
class IssuedAtClaim extends RegisteredClaim
{
	/**
	 * Constructor
	 *
	 * @param int $issue_time Issued at time
	 */
	public function __construct($issue_time) {
		parent::__construct(self::NAME_ISSUED_AT, $issue_time);
	}
}
