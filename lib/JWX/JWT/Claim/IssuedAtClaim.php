<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Feature\NumericDateClaim;


/**
 * Implements 'Issued At' claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.6
 */
class IssuedAtClaim extends RegisteredClaim
{
	use NumericDateClaim;
	
	/**
	 * Constructor
	 *
	 * @param int $issue_time Issued at time
	 */
	public function __construct($issue_time) {
		parent::__construct(self::NAME_ISSUED_AT, intval($issue_time));
	}
	
	/**
	 * Initialize with time set to current time
	 *
	 * @return self
	 */
	public static function now() {
		return new self(time());
	}
}
