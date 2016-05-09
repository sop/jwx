<?php

namespace JWX\JWE\KeyAlgorithm\Feature;


/**
 * Trait for key algorithms employing random CEK generation.
 */
trait RandomCEK
{
	public function cekForEncryption($length) {
		$ret = openssl_random_pseudo_bytes($length);
		if (false === $ret) {
			throw new \RuntimeException("openssl_random_pseudo_bytes() failed.");
		}
		return $ret;
	}
}
