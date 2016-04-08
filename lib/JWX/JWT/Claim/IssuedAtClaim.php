<?php

namespace JWX\JWT\Claim;


class IssuedAtClaim extends RegisteredClaim
{
	public function __construct($value) {
		parent::__construct(self::NAME_ISSUED_AT, $value);
	}
}
