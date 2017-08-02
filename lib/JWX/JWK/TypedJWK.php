<?php

namespace JWX\JWK;

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
     * @return \JWX\JWK\Parameter\JWKParameter
     */
    abstract public function get($name);
    
    /**
     * Check whether the algorithm parameter is present.
     *
     * @return bool
     */
    public function hasAlgorithmParameter()
    {
        return $this->has(Parameter\JWKParameter::P_ALG);
    }
    
    /**
     * Get the algorithm parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\AlgorithmParameter
     */
    public function algorithmParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_ALG),
            Parameter\AlgorithmParameter::class);
    }
    
    /**
     * Check whether the curve parameter is present.
     *
     * @return bool
     */
    public function hasCurveParameter()
    {
        return $this->has(Parameter\JWKParameter::P_CRV);
    }
    
    /**
     * Get the curve parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\CurveParameter
     */
    public function curveParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_CRV),
            Parameter\CurveParameter::class);
    }
    
    /**
     * Check whether the ECC private key parameter is present.
     *
     * @return bool
     */
    public function hasECCPrivateKeyParameter()
    {
        return $this->has(Parameter\JWKParameter::P_ECC_D);
    }
    
    /**
     * Get the ECC private key parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\ECCPrivateKeyParameter
     */
    public function ECCPrivateKeyParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_ECC_D),
            Parameter\ECCPrivateKeyParameter::class);
    }
    
    /**
     * Check whether the exponent parameter is present.
     *
     * @return bool
     */
    public function hasExponentParameter()
    {
        return $this->has(Parameter\JWKParameter::P_E);
    }
    
    /**
     * Get the exponent parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\ExponentParameter
     */
    public function exponentParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_E),
            Parameter\ExponentParameter::class);
    }
    
    /**
     * Check whether the first CRT coefficient parameter is present.
     *
     * @return bool
     */
    public function hasFirstCRTCoefficientParameter()
    {
        return $this->has(Parameter\JWKParameter::P_QI);
    }
    
    /**
     * Get the first CRT coefficient parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\FirstCRTCoefficientParameter
     */
    public function firstCRTCoefficientParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_QI),
            Parameter\FirstCRTCoefficientParameter::class);
    }
    
    /**
     * Check whether the first factor CRT exponent parameter is present.
     *
     * @return bool
     */
    public function hasFirstFactorCRTExponentParameter()
    {
        return $this->has(Parameter\JWKParameter::P_DP);
    }
    
    /**
     * Get the first factor CRT exponent parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\FirstFactorCRTExponentParameter
     */
    public function firstFactorCRTExponentParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_DP),
            Parameter\FirstFactorCRTExponentParameter::class);
    }
    
    /**
     * Check whether the first prime factor parameter is present.
     *
     * @return bool
     */
    public function hasFirstPrimeFactorParameter()
    {
        return $this->has(Parameter\JWKParameter::P_P);
    }
    
    /**
     * Get the first prime factor parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\FirstPrimeFactorParameter
     */
    public function firstPrimeFactorParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_P),
            Parameter\FirstPrimeFactorParameter::class);
    }
    
    /**
     * Check whether the key ID parameter is present.
     *
     * @return bool
     */
    public function hasKeyIDParameter()
    {
        return $this->has(Parameter\JWKParameter::P_KID);
    }
    
    /**
     * Get the key ID parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\KeyIDParameter
     */
    public function keyIDParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_KID),
            Parameter\KeyIDParameter::class);
    }
    
    /**
     * Check whether the key operations parameter is present.
     *
     * @return bool
     */
    public function hasKeyOperationsParameter()
    {
        return $this->has(Parameter\JWKParameter::P_KEY_OPS);
    }
    
    /**
     * Get the key operations parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\KeyOperationsParameter
     */
    public function keyOperationsParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_KEY_OPS),
            Parameter\KeyOperationsParameter::class);
    }
    
    /**
     * Check whether the key type parameter is present.
     *
     * @return bool
     */
    public function hasKeyTypeParameter()
    {
        return $this->has(Parameter\JWKParameter::P_KTY);
    }
    
    /**
     * Get the key type parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\KeyTypeParameter
     */
    public function keyTypeParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_KTY),
            Parameter\KeyTypeParameter::class);
    }
    
    /**
     * Check whether the key value parameter is present.
     *
     * @return bool
     */
    public function hasKeyValueParameter()
    {
        return $this->has(Parameter\JWKParameter::P_K);
    }
    
    /**
     * Get the key value parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\KeyValueParameter
     */
    public function keyValueParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_K),
            Parameter\KeyValueParameter::class);
    }
    
    /**
     * Check whether the modulus parameter is present.
     *
     * @return bool
     */
    public function hasModulusParameter()
    {
        return $this->has(Parameter\JWKParameter::P_N);
    }
    
    /**
     * Get the modulus parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\ModulusParameter
     */
    public function modulusParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_N),
            Parameter\ModulusParameter::class);
    }
    
    /**
     * Check whether the other primes info parameter is present.
     *
     * @return bool
     */
    public function hasOtherPrimesInfoParameter()
    {
        return $this->has(Parameter\JWKParameter::P_OTH);
    }
    
    /**
     * Get the other primes info parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\OtherPrimesInfoParameter
     */
    public function otherPrimesInfoParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_OTH),
            Parameter\OtherPrimesInfoParameter::class);
    }
    
    /**
     * Check whether the private exponent parameter is present.
     *
     * @return bool
     */
    public function hasPrivateExponentParameter()
    {
        return $this->has(Parameter\JWKParameter::P_RSA_D);
    }
    
    /**
     * Get the private exponent parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\PrivateExponentParameter
     */
    public function privateExponentParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_RSA_D),
            Parameter\PrivateExponentParameter::class);
    }
    
    /**
     * Check whether the public key use parameter is present.
     *
     * @return bool
     */
    public function hasPublicKeyUseParameter()
    {
        return $this->has(Parameter\JWKParameter::P_USE);
    }
    
    /**
     * Get the public key use parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\PublicKeyUseParameter
     */
    public function publicKeyUseParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_USE),
            Parameter\PublicKeyUseParameter::class);
    }
    
    /**
     * Check whether the second factor CRT exponent parameter is present.
     *
     * @return bool
     */
    public function hasSecondFactorCRTExponentParameter()
    {
        return $this->has(Parameter\JWKParameter::P_DQ);
    }
    
    /**
     * Get the second factor CRT exponent parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\SecondFactorCRTExponentParameter
     */
    public function secondFactorCRTExponentParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_DQ),
            Parameter\SecondFactorCRTExponentParameter::class);
    }
    
    /**
     * Check whether the second prime factor parameter is present.
     *
     * @return bool
     */
    public function hasSecondPrimeFactorParameter()
    {
        return $this->has(Parameter\JWKParameter::P_Q);
    }
    
    /**
     * Get the second prime factor parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\SecondPrimeFactorParameter
     */
    public function secondPrimeFactorParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_Q),
            Parameter\SecondPrimeFactorParameter::class);
    }
    
    /**
     * Check whether the X.509 certificate chain parameter is present.
     *
     * @return bool
     */
    public function hasX509CertificateChainParameter()
    {
        return $this->has(Parameter\JWKParameter::P_X5C);
    }
    
    /**
     * Get the X.509 certificate chain parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\X509CertificateChainParameter
     */
    public function X509CertificateChainParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_X5C),
            Parameter\X509CertificateChainParameter::class);
    }
    
    /**
     * Check whether the X.509 certificate SHA-1 thumbprint parameter is
     * present.
     *
     * @return bool
     */
    public function hasX509CertificateSHA1ThumbprintParameter()
    {
        return $this->has(Parameter\JWKParameter::P_X5T);
    }
    
    /**
     * Get the X.509 certificate SHA-1 thumbprint parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\X509CertificateSHA1ThumbprintParameter
     */
    public function X509CertificateSHA1ThumbprintParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_X5T),
            Parameter\X509CertificateSHA1ThumbprintParameter::class);
    }
    
    /**
     * Check whether the X.509 certificate SHA-256 thumbprint parameter is
     * present.
     *
     * @return bool
     */
    public function hasX509CertificateSHA256ThumbprintParameter()
    {
        return $this->has(Parameter\JWKParameter::P_X5TS256);
    }
    
    /**
     * Get the X.509 certificate SHA-256 thumbprint parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\X509CertificateSHA256ThumbprintParameter
     */
    public function X509CertificateSHA256ThumbprintParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_X5TS256),
            Parameter\X509CertificateSHA256ThumbprintParameter::class);
    }
    
    /**
     * Check whether the X.509 URL parameter is present.
     *
     * @return bool
     */
    public function hasX509URLParameter()
    {
        return $this->has(Parameter\JWKParameter::P_X5U);
    }
    
    /**
     * Get the X.509 URL parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\X509URLParameter
     */
    public function X509URLParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_X5U),
            Parameter\X509URLParameter::class);
    }
    
    /**
     * Check whether the X coordinate parameter is present.
     *
     * @return bool
     */
    public function hasXCoordinateParameter()
    {
        return $this->has(Parameter\JWKParameter::P_X);
    }
    
    /**
     * Get the X coordinate parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\XCoordinateParameter
     */
    public function XCoordinateParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_X),
            Parameter\XCoordinateParameter::class);
    }
    
    /**
     * Check whether the Y coordinate parameter is present.
     *
     * @return bool
     */
    public function hasYCoordinateParameter()
    {
        return $this->has(Parameter\JWKParameter::P_Y);
    }
    
    /**
     * Get the Y coordinate parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException If the parameter is not present
     * @return Parameter\YCoordinateParameter
     */
    public function YCoordinateParameter()
    {
        return self::_checkType($this->get(Parameter\JWKParameter::P_Y),
            Parameter\YCoordinateParameter::class);
    }
    
    /**
     * Check that the parameter is an instance of the given class.
     *
     * @param Parameter\JWKParameter $param Parameter
     * @param string $cls Class name
     * @throws \UnexpectedValueException
     * @return Parameter\JWKParameter
     */
    private static function _checkType(Parameter\JWKParameter $param, $cls)
    {
        if (!$param instanceof $cls) {
            throw new \UnexpectedValueException(
                "$cls expected, got " . get_class($param));
        }
        return $param;
    }
}
