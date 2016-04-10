<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Validator\ContainsValidator;


/**
 * Implements 'aud' claim specified in rfc7519 section 4.1.3
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1.3
 */
class AudienceClaim extends RegisteredClaim
{
	/**
	 * Constructor
	 *
	 * @param string ...$audiences One or more audiences
	 */
	public function __construct(...$audiences) {
		parent::__construct(self::NAME_AUDIENCE, $audiences, 
			new ContainsValidator());
	
	}
	
	public static function fromJSONValue($value) {
		return is_array($value) ? new self(...$value) : new self($value);
	}
}
