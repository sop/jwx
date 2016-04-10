<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Validator\EqualsValidator;


/**
 * Implements 'sub' claim specified in rfc7519 section 4.1.2
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.2
 */
class SubjectClaim extends RegisteredClaim
{
	/**
	 * Constructor
	 *
	 * @param string $subject Subject
	 */
	public function __construct($subject) {
		parent::__construct(self::NAME_SUBJECT, $subject, new EqualsValidator());
	}
}
