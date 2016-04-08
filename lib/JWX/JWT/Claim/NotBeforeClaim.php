<?php

namespace JWX\JWT\Claim;


class NotBeforeClaim extends RegisteredClaim
{
	public function __construct($value) {
		parent::__construct(self::NAME_NOT_BEFORE, $value);
	}
}
