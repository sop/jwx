<?php

namespace JWX\JWT\Claim;


class ExpirationTimeClaim extends RegisteredClaim
{
	public function __construct($value) {
		parent::__construct(self::NAME_EXPIRATION_TIME, $value);
	}
}
