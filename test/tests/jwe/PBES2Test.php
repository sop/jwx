<?php

use JWX\JWA\JWA;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\PBES2Algorithm;
use JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;


/**
 * @group jwe
 */
class PBES2Test extends PHPUnit_Framework_TestCase
{
	const PASSWORD = "password";
	const SALT = "salt";
	const COUNT = 256;
	const CEK_A128 = "123456789 123456789 123456789 12";
	
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
	public function testSalt(PBES2Algorithm $algo) {
		$this->assertEquals(self::SALT, $algo->saltInput());
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
	 * @param PBES2Algorithm $algo
	 */
	public function testAlgoValue(PBES2Algorithm $algo) {
		$this->assertEquals(JWA::ALGO_PBES2_HS256_A128KW, 
			$algo->algorithmParamValue());
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param PBES2Algorithm $algo
	 */
	public function testEncryptCEK(PBES2Algorithm $algo) {
		$data = $algo->encrypt(self::CEK_A128);
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testCreate
	 * @depends testEncryptCEK
	 *
	 * @param PBES2Algorithm $algo
	 */
	public function testDecryptCEK(PBES2Algorithm $algo, $data) {
		$cek = $algo->decrypt($data);
		$this->assertEquals(self::CEK_A128, $cek);
	}
	
	public function testFromPassword() {
		$algo = PBES2HS256A128KWAlgorithm::fromPassword(self::PASSWORD);
		$this->assertInstanceOf(PBES2Algorithm::class, $algo);
	}
}