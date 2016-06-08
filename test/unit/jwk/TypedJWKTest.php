<?php

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\Parameter\CurveParameter;
use JWX\JWK\Parameter\ECCPrivateKeyParameter;
use JWX\JWK\Parameter\ExponentParameter;
use JWX\JWK\Parameter\FirstCRTCoefficientParameter;
use JWX\JWK\Parameter\FirstFactorCRTExponentParameter;
use JWX\JWK\Parameter\FirstPrimeFactorParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyIDParameter;
use JWX\JWK\Parameter\KeyOperationsParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\KeyValueParameter;
use JWX\JWK\Parameter\ModulusParameter;
use JWX\JWK\Parameter\OtherPrimesInfoParameter;
use JWX\JWK\Parameter\PrivateExponentParameter;
use JWX\JWK\Parameter\PublicKeyUseParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\SecondFactorCRTExponentParameter;
use JWX\JWK\Parameter\SecondPrimeFactorParameter;
use JWX\JWK\Parameter\XCoordinateParameter;
use JWX\JWK\Parameter\YCoordinateParameter;


/**
 * @group jwk
 */
class TypedJWKTest extends PHPUnit_Framework_TestCase
{
	private static $_jwk;
	
	public static function setUpBeforeClass() {
		self::$_jwk = new JWK(new AlgorithmParameter(JWA::ALGO_NONE), 
			new CurveParameter(CurveParameter::CURVE_P256), 
			ECCPrivateKeyParameter::fromString("\xff"), 
			ExponentParameter::fromNumber(42), 
			FirstCRTCoefficientParameter::fromNumber(42), 
			FirstFactorCRTExponentParameter::fromNumber(42), 
			FirstPrimeFactorParameter::fromNumber(42), 
			new KeyIDParameter("test"), 
			new KeyOperationsParameter(KeyOperationsParameter::OP_SIGN), 
			new KeyTypeParameter(KeyTypeParameter::TYPE_OCT), 
			KeyValueParameter::fromString("test"), 
			ModulusParameter::fromNumber(42), new OtherPrimesInfoParameter(), 
			new PublicKeyUseParameter(PublicKeyUseParameter::USE_SIGNATURE), 
			SecondFactorCRTExponentParameter::fromNumber(42), 
			SecondPrimeFactorParameter::fromNumber(42), 
			XCoordinateParameter::fromString("\ff"), 
			YCoordinateParameter::fromString("\xff"));
	}
	
	public static function tearDownAfterClass() {
		self::$_jwk = null;
	}
	
	public function testHasAlgorithm() {
		$this->assertTrue(self::$_jwk->hasAlgorithmParameter());
	}
	
	public function testAlgorithm() {
		$this->assertInstanceOf(AlgorithmParameter::class, 
			self::$_jwk->algorithmParameter());
	}
	
	public function testHasCurve() {
		$this->assertTrue(self::$_jwk->hasCurveParameter());
	}
	
	public function testCurve() {
		$this->assertInstanceOf(CurveParameter::class, 
			self::$_jwk->curveParameter());
	}
	
	public function testHasECCPrivateKey() {
		$this->assertTrue(self::$_jwk->hasECCPrivateKeyParameter());
	}
	
	public function testECCPrivateKey() {
		$this->assertInstanceOf(ECCPrivateKeyParameter::class, 
			self::$_jwk->ECCPrivateKeyParameter());
	}
	
	public function testHasExponent() {
		$this->assertTrue(self::$_jwk->hasExponentParameter());
	}
	
	public function testExponent() {
		$this->assertInstanceOf(ExponentParameter::class, 
			self::$_jwk->exponentParameter());
	}
	
	public function testHasFirstCRTCoefficient() {
		$this->assertTrue(self::$_jwk->hasFirstCRTCoefficientParameter());
	}
	
	public function testFirstCRTCoefficient() {
		$this->assertInstanceOf(FirstCRTCoefficientParameter::class, 
			self::$_jwk->firstCRTCoefficientParameter());
	}
	
	public function testHasFirstFactorCRTExponent() {
		$this->assertTrue(self::$_jwk->hasFirstFactorCRTExponentParameter());
	}
	
	public function testFirstFactorCRTExponent() {
		$this->assertInstanceOf(FirstFactorCRTExponentParameter::class, 
			self::$_jwk->firstFactorCRTExponentParameter());
	}
	
	public function testHasFirstPrimeFactor() {
		$this->assertTrue(self::$_jwk->hasFirstPrimeFactorParameter());
	}
	
	public function testFirstPrimeFactor() {
		$this->assertInstanceOf(FirstPrimeFactorParameter::class, 
			self::$_jwk->firstPrimeFactorParameter());
	}
	
	public function testHasKeyID() {
		$this->assertTrue(self::$_jwk->hasKeyIDParameter());
	}
	
	public function testKeyID() {
		$this->assertInstanceOf(KeyIDParameter::class, 
			self::$_jwk->keyIDParameter());
	}
	
	public function testHasKeyOperations() {
		$this->assertTrue(self::$_jwk->hasKeyOperationsParameter());
	}
	
	public function testKeyOperations() {
		$this->assertInstanceOf(KeyOperationsParameter::class, 
			self::$_jwk->keyOperationsParameter());
	}
	
	public function testHasKeyType() {
		$this->assertTrue(self::$_jwk->hasKeyTypeParameter());
	}
	
	public function testKeyType() {
		$this->assertInstanceOf(KeyTypeParameter::class, 
			self::$_jwk->keyTypeParameter());
	}
	
	public function testHasKeyValue() {
		$this->assertTrue(self::$_jwk->hasKeyValueParameter());
	}
	
	public function testKeyValue() {
		$this->assertInstanceOf(KeyValueParameter::class, 
			self::$_jwk->keyValueParameter());
	}
	
	public function testHasModulus() {
		$this->assertTrue(self::$_jwk->hasModulusParameter());
	}
	
	public function testModulus() {
		$this->assertInstanceOf(ModulusParameter::class, 
			self::$_jwk->modulusParameter());
	}
	
	public function testHasOtherPrimesInfo() {
		$this->assertTrue(self::$_jwk->hasOtherPrimesInfoParameter());
	}
	
	public function testOtherPrimesInfo() {
		$this->assertInstanceOf(OtherPrimesInfoParameter::class, 
			self::$_jwk->otherPrimesInfoParameter());
	}
	
	public function testHasPrivateExponentParameter() {
		$jwk = new JWK(PrivateExponentParameter::fromNumber(42));
		$this->assertTrue($jwk->hasPrivateExponentParameter());
	}
	
	public function testPrivateExponentParameter() {
		$jwk = new JWK(PrivateExponentParameter::fromNumber(42));
		$this->assertInstanceOf(PrivateExponentParameter::class, 
			$jwk->privateExponentParameter());
	}
	
	public function testHasPublicKeyUse() {
		$this->assertTrue(self::$_jwk->hasPublicKeyUseParameter());
	}
	
	public function testPublicKeyUse() {
		$this->assertInstanceOf(PublicKeyUseParameter::class, 
			self::$_jwk->publicKeyUseParameter());
	}
	
	public function testHasSecondFactorCRTExponent() {
		$this->assertTrue(self::$_jwk->hasSecondFactorCRTExponentParameter());
	}
	
	public function testSecondFactorCRTExponent() {
		$this->assertInstanceOf(SecondFactorCRTExponentParameter::class, 
			self::$_jwk->secondFactorCRTExponentParameter());
	}
	
	public function testHasSecondPrimeFactor() {
		$this->assertTrue(self::$_jwk->hasSecondPrimeFactorParameter());
	}
	
	public function testSecondPrimeFactor() {
		$this->assertInstanceOf(SecondPrimeFactorParameter::class, 
			self::$_jwk->secondPrimeFactorParameter());
	}
	
	public function testHasXCoordinate() {
		$this->assertTrue(self::$_jwk->hasXCoordinateParameter());
	}
	
	public function testXCoordinate() {
		$this->assertInstanceOf(XCoordinateParameter::class, 
			self::$_jwk->XCoordinateParameter());
	}
	
	public function testHasYCoordinate() {
		$this->assertTrue(self::$_jwk->hasYCoordinateParameter());
	}
	
	public function testYCoordinate() {
		$this->assertInstanceOf(YCoordinateParameter::class, 
			self::$_jwk->YCoordinateParameter());
	}
	
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testTypeFails() {
		$jwk = new JWK(
			new JWKParameter(RegisteredJWKParameter::P_ALG, JWA::ALGO_NONE));
		$jwk->algorithmParameter();
	}
}
