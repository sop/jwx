<?php

namespace JWX\JWT\Claim;


class AudienceClaim extends RegisteredClaim
{
	public function __construct($value) {
		parent::__construct(self::NAME_AUDIENCE, $value);
	}
}
