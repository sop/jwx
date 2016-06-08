<?php

namespace JWX\JWK;

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
 * Trait for JWK to provide parameter accessor methods for typed return values.
 */
trait TypedJWK
{
	/**
	 * Whether parameters are present.
	 *
	 * @param string ...$names Parameter names
	 * @return bool
	 */
	abstract public function has(...$names);
	
	/**
	 * Get a parameter.
	 *
	 * @param string $name Parameter name
	 * @return JWKParameter
	 */
	abstract public function get($name);
	
	/**
	 * Check whether the algorithm parameter is present.
	 *
	 * @return bool
	 */
	public function hasAlgorithmParameter() {
		return $this->has(RegisteredJWKParameter::P_ALG);
	}
	
	/**
	 * Get the algorithm parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return AlgorithmParameter
	 */
	public function algorithmParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_ALG), 
			AlgorithmParameter::class);
	}
	
	/**
	 * Check whether the curve parameter is present.
	 *
	 * @return bool
	 */
	public function hasCurveParameter() {
		return $this->has(RegisteredJWKParameter::P_CRV);
	}
	
	/**
	 * Get the curve parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return CurveParameter
	 */
	public function curveParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_CRV), 
			CurveParameter::class);
	}
	
	/**
	 * Check whether the ECC private key parameter is present.
	 *
	 * @return bool
	 */
	public function hasECCPrivateKeyParameter() {
		return $this->has(RegisteredJWKParameter::P_ECC_D);
	}
	
	/**
	 * Get the ECC private key parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return ECCPrivateKeyParameter
	 */
	public function ECCPrivateKeyParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_ECC_D), 
			ECCPrivateKeyParameter::class);
	}
	
	/**
	 * Check whether the exponent parameter is present.
	 *
	 * @return bool
	 */
	public function hasExponentParameter() {
		return $this->has(RegisteredJWKParameter::P_E);
	}
	
	/**
	 * Get the exponent parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return ExponentParameter
	 */
	public function exponentParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_E), 
			ExponentParameter::class);
	}
	
	/**
	 * Check whether the first CRT coefficient parameter is present.
	 *
	 * @return bool
	 */
	public function hasFirstCRTCoefficientParameter() {
		return $this->has(RegisteredJWKParameter::P_QI);
	}
	
	/**
	 * Get the first CRT coefficient parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return FirstCRTCoefficientParameter
	 */
	public function firstCRTCoefficientParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_QI), 
			FirstCRTCoefficientParameter::class);
	}
	
	/**
	 * Check whether the first factor CRT exponent parameter is present.
	 *
	 * @return bool
	 */
	public function hasFirstFactorCRTExponentParameter() {
		return $this->has(RegisteredJWKParameter::P_DP);
	}
	
	/**
	 * Get the first factor CRT exponent parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return FirstFactorCRTExponentParameter
	 */
	public function firstFactorCRTExponentParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_DP), 
			FirstFactorCRTExponentParameter::class);
	}
	
	/**
	 * Check whether the first prime factor parameter is present.
	 *
	 * @return bool
	 */
	public function hasFirstPrimeFactorParameter() {
		return $this->has(RegisteredJWKParameter::P_P);
	}
	
	/**
	 * Get the first prime factor parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return FirstPrimeFactorParameter
	 */
	public function firstPrimeFactorParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_P), 
			FirstPrimeFactorParameter::class);
	}
	
	/**
	 * Check whether the key ID parameter is present.
	 *
	 * @return bool
	 */
	public function hasKeyIDParameter() {
		return $this->has(RegisteredJWKParameter::P_KID);
	}
	
	/**
	 * Get the key ID parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return KeyIDParameter
	 */
	public function keyIDParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_KID), 
			KeyIDParameter::class);
	}
	
	/**
	 * Check whether the key operations parameter is present.
	 *
	 * @return bool
	 */
	public function hasKeyOperationsParameter() {
		return $this->has(RegisteredJWKParameter::P_KEY_OPS);
	}
	
	/**
	 * Get the key operations parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return KeyOperationsParameter
	 */
	public function keyOperationsParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_KEY_OPS), 
			KeyOperationsParameter::class);
	}
	
	/**
	 * Check whether the key type parameter is present.
	 *
	 * @return bool
	 */
	public function hasKeyTypeParameter() {
		return $this->has(RegisteredJWKParameter::P_KTY);
	}
	
	/**
	 * Get the key type parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return KeyTypeParameter
	 */
	public function keyTypeParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_KTY), 
			KeyTypeParameter::class);
	}
	
	/**
	 * Check whether the key value parameter is present.
	 *
	 * @return bool
	 */
	public function hasKeyValueParameter() {
		return $this->has(RegisteredJWKParameter::P_K);
	}
	
	/**
	 * Get the key value parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return KeyValueParameter
	 */
	public function keyValueParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_K), 
			KeyValueParameter::class);
	}
	
	/**
	 * Check whether the modulus parameter is present.
	 *
	 * @return bool
	 */
	public function hasModulusParameter() {
		return $this->has(RegisteredJWKParameter::P_N);
	}
	
	/**
	 * Get the modulus parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return ModulusParameter
	 */
	public function modulusParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_N), 
			ModulusParameter::class);
	}
	
	/**
	 * Check whether the other primes info parameter is present.
	 *
	 * @return bool
	 */
	public function hasOtherPrimesInfoParameter() {
		return $this->has(RegisteredJWKParameter::P_OTH);
	}
	
	/**
	 * Get the other primes info parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return OtherPrimesInfoParameter
	 */
	public function otherPrimesInfoParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_OTH), 
			OtherPrimesInfoParameter::class);
	}
	
	/**
	 * Check whether the private exponent parameter is present.
	 *
	 * @return bool
	 */
	public function hasPrivateExponentParameter() {
		return $this->has(RegisteredJWKParameter::P_RSA_D);
	}
	
	/**
	 * Get the private exponent parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return PrivateExponentParameter
	 */
	public function privateExponentParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_RSA_D), 
			PrivateExponentParameter::class);
	}
	
	/**
	 * Check whether the public key use parameter is present.
	 *
	 * @return bool
	 */
	public function hasPublicKeyUseParameter() {
		return $this->has(RegisteredJWKParameter::P_USE);
	}
	
	/**
	 * Get the public key use parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return PublicKeyUseParameter
	 */
	public function publicKeyUseParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_USE), 
			PublicKeyUseParameter::class);
	}
	
	/**
	 * Check whether the second factor CRT exponent parameter is present.
	 *
	 * @return bool
	 */
	public function hasSecondFactorCRTExponentParameter() {
		return $this->has(RegisteredJWKParameter::P_DQ);
	}
	
	/**
	 * Get the second factor CRT exponent parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return SecondFactorCRTExponentParameter
	 */
	public function secondFactorCRTExponentParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_DQ), 
			SecondFactorCRTExponentParameter::class);
	}
	
	/**
	 * Check whether the second prime factor parameter is present.
	 *
	 * @return bool
	 */
	public function hasSecondPrimeFactorParameter() {
		return $this->has(RegisteredJWKParameter::P_Q);
	}
	
	/**
	 * Get the second prime factor parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return SecondPrimeFactorParameter
	 */
	public function secondPrimeFactorParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_Q), 
			SecondPrimeFactorParameter::class);
	}
	
	/**
	 * Check whether the X coordinate parameter is present.
	 *
	 * @return bool
	 */
	public function hasXCoordinateParameter() {
		return $this->has(RegisteredJWKParameter::P_X);
	}
	
	/**
	 * Get the X coordinate parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return XCoordinateParameter
	 */
	public function XCoordinateParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_X), 
			XCoordinateParameter::class);
	}
	
	/**
	 * Check whether the Y coordinate parameter is present.
	 *
	 * @return bool
	 */
	public function hasYCoordinateParameter() {
		return $this->has(RegisteredJWKParameter::P_Y);
	}
	
	/**
	 * Get the Y coordinate parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return YCoordinateParameter
	 */
	public function YCoordinateParameter() {
		return self::_checkType($this->get(RegisteredJWKParameter::P_Y), 
			YCoordinateParameter::class);
	}
	
	/**
	 * Check that the parameter is an instance of the given class.
	 *
	 * @param JWKParameter $param Parameter
	 * @param string $cls Class name
	 * @throws \UnexpectedValueException
	 * @return JWKParameter
	 */
	private static function _checkType(JWKParameter $param, $cls) {
		if (!$param instanceof $cls) {
			throw new \UnexpectedValueException(
				"$cls expected, got " . get_class($param));
		}
		return $param;
	}
}
