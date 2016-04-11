<?php

namespace JWX\JWK\Parameter;


class KeyIDParameter extends RegisteredJWKParameter
{
	public function __construct($algo) {
		parent::__construct(self::PARAM_KEY_ID, $algo);
	}
}
