<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'Algorithm' parameter for JWS/JWE headers.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.1
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.1
 */
class AlgorithmParameter extends JWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $algo Algorithm name
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_ALGORITHM, (string) $algo);
	}
	
	/**
	 * Initialize from AlgorithmParameterValue.
	 *
	 * @param AlgorithmParameterValue $value
	 * @return self
	 */
	public static function fromAlgorithm(AlgorithmParameterValue $value) {
		return new self($value->algorithmParamValue());
	}
}
