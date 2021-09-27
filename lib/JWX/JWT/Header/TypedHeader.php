<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Header;

use Sop\JWX\JWT\Parameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * Trait for Header to provide parameter accessor methods for typed return
 * values.
 */
trait TypedHeader
{
    /**
     * Whether parameters are present.
     *
     * @param string ...$names Parameter names
     */
    abstract public function has(string ...$names): bool;

    /**
     * Get a parameter.
     *
     * @param string $name Parameter name
     *
     * @throws \LogicException If the parameter is not present
     */
    abstract public function get(string $name): JWTParameter;

    /**
     * Check whether the algorithm parameter is present.
     */
    public function hasAlgorithm(): bool
    {
        return $this->has(Parameter\JWTParameter::P_ALG);
    }

    /**
     * Get the algorithm parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\AlgorithmParameter
     */
    public function algorithm(): Parameter\AlgorithmParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_ALG),
            Parameter\AlgorithmParameter::class);
    }

    /**
     * Check whether the authentication tag parameter is present.
     */
    public function hasAuthenticationTag(): bool
    {
        return $this->has(Parameter\JWTParameter::P_TAG);
    }

    /**
     * Get the authentication tag parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\AuthenticationTagParameter
     */
    public function authenticationTag(): Parameter\AuthenticationTagParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_TAG),
            Parameter\AuthenticationTagParameter::class);
    }

    /**
     * Check whether the 'base64url-encode payload' parameter is present.
     */
    public function hasB64Payload(): bool
    {
        return $this->has(Parameter\JWTParameter::P_B64);
    }

    /**
     * Get the 'base64url-encode payload' parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\B64PayloadParameter
     */
    public function B64Payload(): Parameter\B64PayloadParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_B64),
            Parameter\B64PayloadParameter::class);
    }

    /**
     * Check whether the compression algorithm parameter is present.
     */
    public function hasCompressionAlgorithm(): bool
    {
        return $this->has(Parameter\JWTParameter::P_ZIP);
    }

    /**
     * Get the compression algorithm parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\CompressionAlgorithmParameter
     */
    public function compressionAlgorithm(): Parameter\CompressionAlgorithmParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_ZIP),
            Parameter\CompressionAlgorithmParameter::class);
    }

    /**
     * Check whether the content type parameter is present.
     */
    public function hasContentType(): bool
    {
        return $this->has(Parameter\JWTParameter::P_CTY);
    }

    /**
     * Get the content type parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\ContentTypeParameter
     */
    public function contentType(): Parameter\ContentTypeParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_CTY),
            Parameter\ContentTypeParameter::class);
    }

    /**
     * Check whether the critical parameter is present.
     */
    public function hasCritical(): bool
    {
        return $this->has(Parameter\JWTParameter::P_CRIT);
    }

    /**
     * Get the critical parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\CriticalParameter
     */
    public function critical(): Parameter\CriticalParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_CRIT),
            Parameter\CriticalParameter::class);
    }

    /**
     * Check whether the encryption algorithm parameter is present.
     */
    public function hasEncryptionAlgorithm(): bool
    {
        return $this->has(Parameter\JWTParameter::P_ENC);
    }

    /**
     * Get the encryption algorithm parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\EncryptionAlgorithmParameter
     */
    public function encryptionAlgorithm(): Parameter\EncryptionAlgorithmParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_ENC),
            Parameter\EncryptionAlgorithmParameter::class);
    }

    /**
     * Check whether the initialization vector parameter is present.
     */
    public function hasInitializationVector(): bool
    {
        return $this->has(Parameter\JWTParameter::P_IV);
    }

    /**
     * Get the initialization vector parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\InitializationVectorParameter
     */
    public function initializationVector(): Parameter\InitializationVectorParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_IV),
            Parameter\InitializationVectorParameter::class);
    }

    /**
     * Check whether the JSON web key parameter is present.
     */
    public function hasJSONWebKey(): bool
    {
        return $this->has(Parameter\JWTParameter::P_JWK);
    }

    /**
     * Get the JSON web key parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\JSONWebKeyParameter
     */
    public function JSONWebKey(): Parameter\JSONWebKeyParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_JWK),
            Parameter\JSONWebKeyParameter::class);
    }

    /**
     * Check whether the JWK set URL parameter is present.
     */
    public function hasJWKSetURL(): bool
    {
        return $this->has(Parameter\JWTParameter::P_JKU);
    }

    /**
     * Get the JWK set URL parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\JWKSetURLParameter
     */
    public function JWKSetURL(): Parameter\JWKSetURLParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_JKU),
            Parameter\JWKSetURLParameter::class);
    }

    /**
     * Check whether the key ID parameter is present.
     */
    public function hasKeyID(): bool
    {
        return $this->has(Parameter\JWTParameter::P_KID);
    }

    /**
     * Get the key ID parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\KeyIDParameter
     */
    public function keyID(): Parameter\KeyIDParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_KID),
            Parameter\KeyIDParameter::class);
    }

    /**
     * Check whether the PBES2 count parameter is present.
     */
    public function hasPBES2Count(): bool
    {
        return $this->has(Parameter\JWTParameter::P_P2C);
    }

    /**
     * Get the PBES2 count parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\PBES2CountParameter
     */
    public function PBES2Count(): Parameter\PBES2CountParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_P2C),
            Parameter\PBES2CountParameter::class);
    }

    /**
     * Check whether the PBES2 salt input parameter is present.
     */
    public function hasPBES2SaltInput(): bool
    {
        return $this->has(Parameter\JWTParameter::P_P2S);
    }

    /**
     * Get the PBES2 salt input parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\PBES2SaltInputParameter
     */
    public function PBES2SaltInput(): Parameter\PBES2SaltInputParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_P2S),
            Parameter\PBES2SaltInputParameter::class);
    }

    /**
     * Check whether the type parameter is present.
     */
    public function hasType(): bool
    {
        return $this->has(Parameter\JWTParameter::P_TYP);
    }

    /**
     * Get the type parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\TypeParameter
     */
    public function type(): Parameter\TypeParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_TYP),
            Parameter\TypeParameter::class);
    }

    /**
     * Check whether the X.509 certificate chain parameter is present.
     */
    public function hasX509CertificateChain(): bool
    {
        return $this->has(Parameter\JWTParameter::P_X5C);
    }

    /**
     * Get the X.509 certificate chain parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\X509CertificateChainParameter
     */
    public function X509CertificateChain(): Parameter\X509CertificateChainParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_X5C),
            Parameter\X509CertificateChainParameter::class);
    }

    /**
     * Check whether the X.509 certificate SHA-1 thumbprint parameter is
     * present.
     */
    public function hasX509CertificateSHA1Thumbprint(): bool
    {
        return $this->has(Parameter\JWTParameter::P_X5T);
    }

    /**
     * Get the X.509 certificate SHA-1 thumbprint parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\X509CertificateSHA1ThumbprintParameter
     */
    public function X509CertificateSHA1Thumbprint(): Parameter\X509CertificateSHA1ThumbprintParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_X5T),
            Parameter\X509CertificateSHA1ThumbprintParameter::class);
    }

    /**
     * Check whether the X.509 certificate SHA-256 thumbprint parameter is
     * present.
     */
    public function hasX509CertificateSHA256Thumbprint(): bool
    {
        return $this->has(Parameter\JWTParameter::P_X5TS256);
    }

    /**
     * Get the X.509 certificate SHA-256 thumbprint parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\X509CertificateSHA256ThumbprintParameter
     */
    public function X509CertificateSHA256Thumbprint(): Parameter\X509CertificateSHA256ThumbprintParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_X5TS256),
            Parameter\X509CertificateSHA256ThumbprintParameter::class);
    }

    /**
     * Check whether the X.509 URL parameter is present.
     */
    public function hasX509URL(): bool
    {
        return $this->has(Parameter\JWTParameter::P_X5U);
    }

    /**
     * Get the X.509 URL parameter.
     *
     * @throws \UnexpectedValueException If the parameter has a wrong class
     * @throws \LogicException           If the parameter is not present
     *
     * @return \Sop\JWX\JWT\Parameter\X509URLParameter
     */
    public function X509URL(): Parameter\X509URLParameter
    {
        return self::_checkType($this->get(Parameter\JWTParameter::P_X5U),
            Parameter\X509URLParameter::class);
    }

    /**
     * Check that the parameter is an instance of the given class.
     *
     * @param \Sop\JWX\JWT\Parameter\JWTParameter $param Parameter
     * @param string                              $cls   Class name
     *
     * @throws \UnexpectedValueException
     *
     * @return \Sop\JWX\JWT\Parameter\JWTParameter
     */
    private static function _checkType(Parameter\JWTParameter $param, string $cls): Parameter\JWTParameter
    {
        if (!$param instanceof $cls) {
            throw new \UnexpectedValueException(
                "{$cls} expected, got " . get_class($param));
        }
        return $param;
    }
}
