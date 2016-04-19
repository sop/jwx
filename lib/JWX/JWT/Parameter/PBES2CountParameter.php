<?php

namespace JWX\JWT\Parameter;


/**
 * PBES2 Count parameter
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8.1.2
 */
class PBES2CountParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param int $count
	 */
	public function __construct($count) {
		parent::__construct(self::PARAM_PBES2_COUNT, intval($count));
	}
}
