<?php

use JWX\JWE\KeyAlgorithm\A128GCMKWAlgorithm;
use JWX\JWT\Parameter\JWTParameter;


/**
 * @group jwe
 * @group key
 */
class AESGCMKWTest extends PHPUnit_Framework_TestCase
{
	const KEY_128 = "123456789 123456";
	
	const IV = "123456789 12";
	
	public function testHeaderParams() {
		$algo = new A128GCMKWAlgorithm(selF::KEY_128, self::IV);
		$params = $algo->headerParameters();
		$this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
	}
	
	/**
	 * @expectedException LengthException
	 */
	public function testInvalidIVFail() {
		new A128GCMKWAlgorithm(self::KEY_128, "fail");
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testDecryptMissingAuthTag() {
		$algo = new A128GCMKWAlgorithm(selF::KEY_128, self::IV);
		$algo->decrypt("");
	}
}
