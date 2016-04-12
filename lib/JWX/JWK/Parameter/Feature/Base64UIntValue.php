<?php

namespace JWX\JWK\Parameter\Feature;

use JWX\Util\BigInt;
use JWX\Util\Base64;


trait Base64UIntValue
{
	/**
	 * Get value as a number
	 *
	 * @return BigInt
	 */
	public function number() {
		return BigInt::fromBase256(Base64::urlDecode($this->_value));
	}
}