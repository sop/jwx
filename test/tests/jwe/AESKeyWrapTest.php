<?php

use JWX\JWE\KeyAlgorithm\A128KWAlgorithm;
use JWX\JWE\KeyAlgorithm\A192KWAlgorithm;
use JWX\JWE\KeyAlgorithm\A256KWAlgorithm;


/**
 * @group jwe
 */
class AESKeyWrapTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @dataProvider provideCEK
	 *
	 * @param string $cek
	 */
	public function testA128($cek) {
		static $kek = "ffeeddccbbaa99887766554433221100";
		$algo = new A128KWAlgorithm(hex2bin($kek));
		$ciphertext = $algo->encrypt(hex2bin($cek));
		$result = $algo->decrypt($ciphertext);
		$this->assertEquals($cek, bin2hex($result));
	}
	
	/**
	 * @dataProvider provideCEK
	 *
	 * @param string $cek
	 */
	public function testA192($cek) {
		static $kek = "ffeeddccbbaa99887766554433221100ffeeddccbbaa9988";
		$algo = new A192KWAlgorithm(hex2bin($kek));
		$ciphertext = $algo->encrypt(hex2bin($cek));
		$result = $algo->decrypt($ciphertext);
		$this->assertEquals($cek, bin2hex($result));
	}
	
	/**
	 * @dataProvider provideCEK
	 *
	 * @param string $cek
	 */
	public function testA256($cek) {
		static $kek = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
		$algo = new A256KWAlgorithm(hex2bin($kek));
		$ciphertext = $algo->encrypt(hex2bin($cek));
		$result = $algo->decrypt($ciphertext);
		$this->assertEquals($cek, bin2hex($result));
	}
	
	public function provideCEK() {
		return array(
			/* @formatter:off */
			["00112233445566778899aabbccddeeff"],
			["00112233445566778899aabbccddeeff1122334455667788"],
			["00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"],
			/* @formatter:on */
		);
	}
}
