<?php

namespace JWX\JWK\Parameter;


class AlgorithmParameter extends RegisteredJWKParameter
{
	public function __construct($algo) {
		parent::__construct(self::PARAM_ALGORITHM, $algo);
	}
}
