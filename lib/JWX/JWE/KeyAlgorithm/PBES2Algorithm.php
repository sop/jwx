<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWE\KeyManagementAlgorithm;


abstract class PBES2Algorithm implements KeyManagementAlgorithm
{
	/**
	 * Constructor
	 *
	 * @param string $salt Computed salt
	 * @param int $count Iteration count
	 */
	public function __construct($salt, $count) {

	}
	
	public function encrypt($cek) {

	}
	
	public function decrypt($data) {

	}
}
