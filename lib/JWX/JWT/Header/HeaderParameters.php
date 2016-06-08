<?php

namespace JWX\JWT\Header;

use JWX\JWT\Parameter\JWTParameter;


/**
 * Interface for classes providing JOSE header parameters.
 */
interface HeaderParameters
{
	/**
	 * Get an array of JOSE header parameters representing this object.
	 *
	 * @return JWTParameter[]
	 */
	public function headerParameters();
}
