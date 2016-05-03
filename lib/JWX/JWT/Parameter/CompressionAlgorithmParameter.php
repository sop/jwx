<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'Compression Algorithm' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.3
 * @link
 *       http://www.iana.org/assignments/jose/jose.xhtml#web-encryption-compression-algorithms
 */
class CompressionAlgorithmParameter extends RegisteredJWTParameter
{
	const ALGO_DEFLATE = "DEF";
	
	/**
	 * Constructor
	 *
	 * @param string $type
	 */
	public function __construct($algo) {
		parent::__construct(self::PARAM_COMPRESSION_ALGORITHM, (string) $algo);
	}
}
