<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'Algorithm' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.4
 */
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
