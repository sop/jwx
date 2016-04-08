<?php

namespace JWX\JWT\Claim;


class SubjectClaim extends RegisteredClaim
{
	public function __construct($value) {
		parent::__construct(self::NAME_SUBJECT, $value);
	}
}
