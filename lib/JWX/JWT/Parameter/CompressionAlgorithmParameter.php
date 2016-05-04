<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'Compression Algorithm' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.3
 */
class CompressionAlgorithmParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $type
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_COMPRESSION_ALGORITHM, (string) $algo);
	}
}
