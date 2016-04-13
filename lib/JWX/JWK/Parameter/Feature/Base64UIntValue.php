<?php

namespace JWX\JWK\Parameter\Feature;

use JWX\Util\BigInt;
use JWX\Util\Base64;


trait Base64UIntValue
{
	/**
	 * Initialize parameter from base10 number
	 *
	 * @param int|string $number
	 * @return self
	 */
	public static function fromNumber($number) {
		$data = BigInt::fromBase10($number)->base256();
		return new static(Base64::urlEncode($data));
	}
	
	/**
	 * Get value as a number
	 *
	 * @return BigInt
	 */
	public function number() {
		return BigInt::fromBase256(Base64::urlDecode($this->_value));
	}
}