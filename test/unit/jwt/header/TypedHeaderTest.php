<?php

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\B64PayloadParameter;
use JWX\JWT\Parameter\CompressionAlgorithmParameter;
use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\JWT\Parameter\CriticalParameter;
use JWX\JWT\Parameter\EncryptionAlgorithmParameter;
use JWX\JWT\Parameter\InitializationVectorParameter;
use JWX\JWT\Parameter\JSONWebKeyParameter;
use JWX\JWT\Parameter\JWKSetURLParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\KeyIDParameter;
use JWX\JWT\Parameter\PBES2CountParameter;
use JWX\JWT\Parameter\PBES2SaltInputParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\TypeParameter;
use JWX\JWT\Parameter\X509CertificateChainParameter;
use JWX\JWT\Parameter\X509CertificateSHA1ThumbprintParameter;
use JWX\JWT\Parameter\X509CertificateSHA256ThumbprintParameter;
use JWX\JWT\Parameter\X509URLParameter;


/**
 * @group jwt
 * @group header
 */
class TypedHeaderTest extends PHPUnit_Framework_TestCase
{
	private static $_header;
	
	public static function setUpBeforeClass() {
		self::$_header = new Header(new AlgorithmParameter(JWA::ALGO_NONE), 
			new AuthenticationTagParameter("tag"), new B64PayloadParameter(true), 
			new CompressionAlgorithmParameter(JWA::ALGO_DEFLATE), 
			new ContentTypeParameter("test"), new CriticalParameter("alg"), 
			new EncryptionAlgorithmParameter(JWA::ALGO_A128GCM), 
			new InitializationVectorParameter("12345678"), 
			new JSONWebKeyParameter(new JWK()), 
			new JWKSetURLParameter("urn:test"), new KeyIDParameter("id"), 
			new PBES2CountParameter(1024), new PBES2SaltInputParameter("abcdef"), 
			new TypeParameter("test"), new X509CertificateChainParameter(""), 
			new X509CertificateSHA1ThumbprintParameter(""), 
			new X509CertificateSHA256ThumbprintParameter(""), 
			new X509URLParameter("urn:test"));
	}
	
	public static function tearDownAfterClass() {
		self::$_header = null;
	}
	
	public function testHasAlgorithm() {
		$this->assertTrue(self::$_header->hasAlgorithm());
	}
	
	public function testAlgorithm() {
		$this->assertInstanceOf(AlgorithmParameter::class, 
			self::$_header->algorithm());
	}
	
	public function testHasAuthenticationTag() {
		$this->assertTrue(self::$_header->hasAuthenticationTag());
	}
	
	public function testAuthenticationTag() {
		$this->assertInstanceOf(AuthenticationTagParameter::class, 
			self::$_header->authenticationTag());
	}
	
	public function testHasB64Payload() {
		$this->assertTrue(self::$_header->hasB64Payload());
	}
	
	public function testB64Payload() {
		$this->assertInstanceOf(B64PayloadParameter::class, 
			self::$_header->B64Payload());
	}
	
	public function testHasCompressionAlgorithm() {
		$this->assertTrue(self::$_header->hasCompressionAlgorithm());
	}
	
	public function testCompressionAlgorithm() {
		$this->assertInstanceOf(CompressionAlgorithmParameter::class, 
			self::$_header->compressionAlgorithm());
	}
	
	public function testHasContentType() {
		$this->assertTrue(self::$_header->hasContentType());
	}
	
	public function testContentType() {
		$this->assertInstanceOf(ContentTypeParameter::class, 
			self::$_header->contentType());
	}
	
	public function testHasCritical() {
		$this->assertTrue(self::$_header->hasCritical());
	}
	
	public function testCritical() {
		$this->assertInstanceOf(CriticalParameter::class, 
			self::$_header->critical());
	}
	
	public function testHasEncryptionAlgorithm() {
		$this->assertTrue(self::$_header->hasEncryptionAlgorithm());
	}
	
	public function testEncryptionAlgorithm() {
		$this->assertInstanceOf(EncryptionAlgorithmParameter::class, 
			self::$_header->encryptionAlgorithm());
	}
	
	public function testHasInitializationVector() {
		$this->assertTrue(self::$_header->hasInitializationVector());
	}
	
	public function testInitializationVector() {
		$this->assertInstanceOf(InitializationVectorParameter::class, 
			self::$_header->initializationVector());
	}
	
	public function testHasJSONWebKey() {
		$this->assertTrue(self::$_header->hasJSONWebKey());
	}
	
	public function testJSONWebKey() {
		$this->assertInstanceOf(JSONWebKeyParameter::class, 
			self::$_header->JSONWebKey());
	}
	
	public function testHasJWKSetURL() {
		$this->assertTrue(self::$_header->hasJWKSetURL());
	}
	
	public function testJWKSetURL() {
		$this->assertInstanceOf(JWKSetURLParameter::class, 
			self::$_header->JWKSetURL());
	}
	
	public function testHasKeyID() {
		$this->assertTrue(self::$_header->hasKeyID());
	}
	
	public function testKeyID() {
		$this->assertInstanceOf(KeyIDParameter::class, self::$_header->keyID());
	}
	
	public function testHasPBES2Count() {
		$this->assertTrue(self::$_header->hasPBES2Count());
	}
	
	public function testPBES2Count() {
		$this->assertInstanceOf(PBES2CountParameter::class, 
			self::$_header->PBES2Count());
	}
	
	public function testHasPBES2SaltInput() {
		$this->assertTrue(self::$_header->hasPBES2SaltInput());
	}
	
	public function testPBES2SaltInput() {
		$this->assertInstanceOf(PBES2SaltInputParameter::class, 
			self::$_header->PBES2SaltInput());
	}
	
	public function testHasType() {
		$this->assertTrue(self::$_header->hasType());
	}
	
	public function testType() {
		$this->assertInstanceOf(TypeParameter::class, self::$_header->type());
	}
	
	public function testHasX509CertificateChain() {
		$this->assertTrue(self::$_header->hasX509CertificateChain());
	}
	
	public function testX509CertificateChain() {
		$this->assertInstanceOf(X509CertificateChainParameter::class, 
			self::$_header->X509CertificateChain());
	}
	
	public function testHasX509CertificateSHA1Thumbprint() {
		$this->assertTrue(self::$_header->hasX509CertificateSHA1Thumbprint());
	}
	
	public function testX509CertificateSHA1Thumbprint() {
		$this->assertInstanceOf(X509CertificateSHA1ThumbprintParameter::class, 
			self::$_header->X509CertificateSHA1Thumbprint());
	}
	
	public function testHasX509CertificateSHA256Thumbprint() {
		$this->assertTrue(self::$_header->hasX509CertificateSHA256Thumbprint());
	}
	
	public function testX509CertificateSHA256Thumbprint() {
		$this->assertInstanceOf(X509CertificateSHA256ThumbprintParameter::class, 
			self::$_header->X509CertificateSHA256Thumbprint());
	}
	
	public function testHasX509URL() {
		$this->assertTrue(self::$_header->hasX509URL());
	}
	
	public function testX509URL() {
		$this->assertInstanceOf(X509URLParameter::class, 
			self::$_header->X509URL());
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testTypeFails() {
		$header = new Header(
			new JWTParameter(RegisteredJWTParameter::P_ALG, JWA::ALGO_NONE));
		$header->algorithm();
	}
}
