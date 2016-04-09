<?php

use JWX\Header\Header;
use JWX\JWT\Claims;
use JWX\JWT\Claim\IssuerClaim;
use JWX\JWT\Claim\SubjectClaim;
use JWX\JWE\JWE;
use JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\EncryptionAlgorithm\A192CBCHS384Algorithm;
use JWX\JWE\EncryptionAlgorithm\A256CBCHS512Algorithm;


/**
 * @group jwe
 */
class DirectCEKTest extends PHPUnit_Framework_TestCase
{
	protected $_claims;
	
	const CEK_A128 = "123456789 123456789 123456789 12";
	const CEK_A192 = "123456789 123456789 123456789 123456789 12345678";
	const CEK_A256 = self::CEK_A128 . self::CEK_A128;
	
	public function setUp() {
		$this->_claims = new Claims(new IssuerClaim("test"), 
			new SubjectClaim("test"));
	}
	
	public function tearDown() {
		$this->_claims = null;
	}
	
	/**
	 *
	 * @return JWE
	 */
	public function testEncryptA128() {
		$jwe = JWE::encrypt($this->_claims->toJSON(), new Header(), 
			new DirectCEKAlgorithm(self::CEK_A128), new A128CBCHS256Algorithm());
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptA128
	 *
	 * @param JWE $jwe
	 * @return string
	 */
	public function testToCompact(JWE $jwe) {
		$data = $jwe->toCompact();
		$this->assertTrue(is_string($data));
		return $data;
	}
	
	/**
	 * @depends testToCompact
	 *
	 * @param string $data
	 */
	public function testFromCompact($data) {
		$jwe = JWE::fromCompact($data);
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testFromCompact
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptA128(JWE $jwe) {
		$payload = $jwe->decrypt(new DirectCEKAlgorithm(self::CEK_A128), 
			new A128CBCHS256Algorithm());
		$this->assertEquals($this->_claims->toJSON(), $payload);
	}
	
	/**
	 *
	 * @return JWE
	 */
	public function testEncryptA192() {
		$jwe = JWE::encrypt($this->_claims->toJSON(), new Header(), 
			new DirectCEKAlgorithm(self::CEK_A192), new A192CBCHS384Algorithm());
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptA192
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptA192(JWE $jwe) {
		$payload = $jwe->decrypt(new DirectCEKAlgorithm(self::CEK_A192), 
			new A192CBCHS384Algorithm());
		$this->assertEquals($this->_claims->toJSON(), $payload);
	}
	
	/**
	 *
	 * @return JWE
	 */
	public function testEncryptA256() {
		$jwe = JWE::encrypt($this->_claims->toJSON(), new Header(), 
			new DirectCEKAlgorithm(self::CEK_A256), new A256CBCHS512Algorithm());
		$this->assertInstanceOf(JWE::class, $jwe);
		return $jwe;
	}
	
	/**
	 * @depends testEncryptA256
	 *
	 * @param JWE $jwe
	 */
	public function testDecryptA256(JWE $jwe) {
		$payload = $jwe->decrypt(new DirectCEKAlgorithm(self::CEK_A256), 
			new A256CBCHS512Algorithm());
		$this->assertEquals($this->_claims->toJSON(), $payload);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testInvalidKeySize() {
		JWE::encrypt($this->_claims->toJSON(), new Header(), 
			new DirectCEKAlgorithm("nope"), new A128CBCHS256Algorithm());
	}
}