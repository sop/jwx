<?php

namespace JWX\JWK\Parameter;


class AlgorithmParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $algo Algorithm name
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_ALGORITHM, $algo);
	}
}
