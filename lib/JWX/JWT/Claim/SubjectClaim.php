<?php

namespace JWX\JWT\Claim;


/**
 * Implements 'sub' claim specified in rfc7519 section 4.1.2
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.2
 */
class SubjectClaim extends RegisteredClaim
{
	public function __construct($subject) {
		parent::__construct(self::NAME_SUBJECT, $subject);
	}
}
