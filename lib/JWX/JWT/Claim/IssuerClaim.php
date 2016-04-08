<?php

namespace JWX\JWT\Claim;


class IssuerClaim extends RegisteredClaim
{
	public function __construct($value) {
		parent::__construct(self::NAME_ISSUER, $value);
	}
}
