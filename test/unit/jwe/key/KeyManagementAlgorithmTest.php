<?php

use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWK;
use JWX\JWT\Header\Header;


/**
 * @group jwe
 * @group key
 */
class KeyManagementAlgorithmTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @expectedException BadMethodCallException
	 */
	public function testFromJWKFail() {
		KeyManagementAlgorithm::fromJWK(new JWK(), new Header());
	}
}
