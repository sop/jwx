<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'Compression Algorithm' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.3
 */
class CompressionAlgorithmParameter extends JWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $algo
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_COMPRESSION_ALGORITHM, (string) $algo);
	}
	
	/**
	 * Initialize from CompressionAlgorithmParameterValue.
	 *
	 * @param CompressionAlgorithmParameterValue $value
	 * @return self
	 */
	public static function fromAlgorithm(
			CompressionAlgorithmParameterValue $value) {
		return new self($value->compressionParamValue());
	}
}
