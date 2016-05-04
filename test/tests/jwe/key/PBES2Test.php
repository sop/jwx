<?php

use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\PBES2Algorithm;
use JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;
use JWX\JWE\KeyManagementAlgorithm;


/**
 * @group jwe
 * @group key
 */
class PBES2Test extends PHPUnit_Framework_TestCase
{
	const PASSWORD = "password";
	const SALT = "salt";
	const COUNT = 256;
	
	public function testCreate() {
		$algo = new PBES2HS256A128KWAlgorithm(self::PASSWORD, self::SALT, 
			self::COUNT);
		$this->assertInstanceOf(PBES2Algorithm::class, $algo);
		return $algo;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBES2Algorithm $algo
	 */
	public function testSaltInput(PBES2Algorithm $algo) {
		$this->assertEquals(self::SALT, $algo->saltInput());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBES2Algorithm $algo
	 */
	public function testSalt(PBES2Algorithm $algo) {
		$salt = $algo->salt();
		$this->assertTrue(is_string($salt));
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBES2Algorithm $algo
	 */
	public function testIterationCount(PBES2Algorithm $algo) {
		$this->assertEquals(self::COUNT, $algo->iterationCount());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param KeyManagementAlgorithm $algo
	 */
	public function testHeaderParameters(KeyManagementAlgorithm $algo) {
		$params = $algo->headerParameters();
		$this->assertCount(3, $params);
	}
	
	public function testFromPassword() {
		$algo = PBES2HS256A128KWAlgorithm::fromPassword(self::PASSWORD);
		$this->assertInstanceOf(PBES2Algorithm::class, $algo);
	}
}