<?php

use JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use JWX\JWE\KeyAlgorithm\AESKWAlgorithm;
use JWX\JWE\KeyManagementAlgorithm;


/**
 * @group jwe
 * @group key
 */
class AESKWTest extends PHPUnit_Framework_TestCase
{
	const KEY_128 = "123456789 123456789 123456789 12";
	
	public function testCreate() {
		$algo = new A128KWAlgorithm(self::KEY_128);
		$this->assertInstanceOf(AESKWAlgorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param KeyManagementAlgorithm $algo
	 */
	public function testHeaderParameters(KeyManagementAlgorithm $algo) {
		$params = $algo->headerParameters();
		$this->assertCount(1, $params);
	}
}
