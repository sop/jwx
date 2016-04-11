<?php

namespace JWX\JWK\Parameter;


class PublicKeyUseParameter extends RegisteredJWKParameter
{
	const USE_SIGNATURE = "sig";
	const USE_ENCRYPTION = "enc";
	
	public function __construct($use) {
		parent::__construct(self::PARAM_PUBLIC_KEY_USE, $use);
	}
}
