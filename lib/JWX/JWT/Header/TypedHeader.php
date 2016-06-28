<?php

namespace JWX\JWT\Header;

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
use JWX\JWT\Parameter\TypeParameter;
use JWX\JWT\Parameter\X509CertificateChainParameter;
use JWX\JWT\Parameter\X509CertificateSHA1ThumbprintParameter;
use JWX\JWT\Parameter\X509CertificateSHA256ThumbprintParameter;
use JWX\JWT\Parameter\X509URLParameter;


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
	 * @return bool
	 */
	abstract public function has(...$names);
	
	/**
	 * Get a parameter.
	 *
	 * @param string $name Parameter name
	 * @throws \LogicException If the parameter is not present
	 * @return JWTParameter
	 */
	abstract public function get($name);
	
	/**
	 * Check whether the algorithm parameter is present.
	 *
	 * @return bool
	 */
	public function hasAlgorithm() {
		return $this->has(JWTParameter::P_ALG);
	}
	
	/**
	 * Get the algorithm parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return AlgorithmParameter
	 */
	public function algorithm() {
		return self::_checkType($this->get(JWTParameter::P_ALG), 
			AlgorithmParameter::class);
	}
	
	/**
	 * Check whether the authentication tag parameter is present.
	 *
	 * @return bool
	 */
	public function hasAuthenticationTag() {
		return $this->has(JWTParameter::P_TAG);
	}
	
	/**
	 * Get the authentication tag parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return AuthenticationTagParameter
	 */
	public function authenticationTag() {
		return self::_checkType($this->get(JWTParameter::P_TAG), 
			AuthenticationTagParameter::class);
	}
	
	/**
	 * Check whether the 'base64url-encode payload' parameter is present.
	 *
	 * @return bool
	 */
	public function hasB64Payload() {
		return $this->has(JWTParameter::P_B64);
	}
	
	/**
	 * Get the 'base64url-encode payload' parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return B64PayloadParameter
	 */
	public function B64Payload() {
		return self::_checkType($this->get(JWTParameter::P_B64), 
			B64PayloadParameter::class);
	}
	
	/**
	 * Check whether the compression algorithm parameter is present.
	 *
	 * @return bool
	 */
	public function hasCompressionAlgorithm() {
		return $this->has(JWTParameter::P_ZIP);
	}
	
	/**
	 * Get the compression algorithm parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return CompressionAlgorithmParameter
	 */
	public function compressionAlgorithm() {
		return self::_checkType($this->get(JWTParameter::P_ZIP), 
			CompressionAlgorithmParameter::class);
	}
	
	/**
	 * Check whether the content type parameter is present.
	 *
	 * @return bool
	 */
	public function hasContentType() {
		return $this->has(JWTParameter::P_CTY);
	}
	
	/**
	 * Get the content type parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return ContentTypeParameter
	 */
	public function contentType() {
		return self::_checkType($this->get(JWTParameter::P_CTY), 
			ContentTypeParameter::class);
	}
	
	/**
	 * Check whether the critical parameter is present.
	 *
	 * @return bool
	 */
	public function hasCritical() {
		return $this->has(JWTParameter::P_CRIT);
	}
	
	/**
	 * Get the critical parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return CriticalParameter
	 */
	public function critical() {
		return self::_checkType($this->get(JWTParameter::P_CRIT), 
			CriticalParameter::class);
	}
	
	/**
	 * Check whether the encryption algorithm parameter is present.
	 *
	 * @return bool
	 */
	public function hasEncryptionAlgorithm() {
		return $this->has(JWTParameter::P_ENC);
	}
	
	/**
	 * Get the encryption algorithm parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return EncryptionAlgorithmParameter
	 */
	public function encryptionAlgorithm() {
		return self::_checkType($this->get(JWTParameter::P_ENC), 
			EncryptionAlgorithmParameter::class);
	}
	
	/**
	 * Check whether the initialization vector parameter is present.
	 *
	 * @return bool
	 */
	public function hasInitializationVector() {
		return $this->has(JWTParameter::P_IV);
	}
	
	/**
	 * Get the initialization vector parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return InitializationVectorParameter
	 */
	public function initializationVector() {
		return self::_checkType($this->get(JWTParameter::P_IV), 
			InitializationVectorParameter::class);
	}
	
	/**
	 * Check whether the JSON web key parameter is present.
	 *
	 * @return bool
	 */
	public function hasJSONWebKey() {
		return $this->has(JWTParameter::P_JWK);
	}
	
	/**
	 * Get the JSON web key parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return JSONWebKeyParameter
	 */
	public function JSONWebKey() {
		return self::_checkType($this->get(JWTParameter::P_JWK), 
			JSONWebKeyParameter::class);
	}
	
	/**
	 * Check whether the JWK set URL parameter is present.
	 *
	 * @return bool
	 */
	public function hasJWKSetURL() {
		return $this->has(JWTParameter::P_JKU);
	}
	
	/**
	 * Get the JWK set URL parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return JWKSetURLParameter
	 */
	public function JWKSetURL() {
		return self::_checkType($this->get(JWTParameter::P_JKU), 
			JWKSetURLParameter::class);
	}
	
	/**
	 * Check whether the key ID parameter is present.
	 *
	 * @return bool
	 */
	public function hasKeyID() {
		return $this->has(JWTParameter::P_KID);
	}
	
	/**
	 * Get the key ID parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return KeyIDParameter
	 */
	public function keyID() {
		return self::_checkType($this->get(JWTParameter::P_KID), 
			KeyIDParameter::class);
	}
	
	/**
	 * Check whether the PBES2 count parameter is present.
	 *
	 * @return bool
	 */
	public function hasPBES2Count() {
		return $this->has(JWTParameter::P_P2C);
	}
	
	/**
	 * Get the PBES2 count parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return PBES2CountParameter
	 */
	public function PBES2Count() {
		return self::_checkType($this->get(JWTParameter::P_P2C), 
			PBES2CountParameter::class);
	}
	
	/**
	 * Check whether the PBES2 salt input parameter is present.
	 *
	 * @return bool
	 */
	public function hasPBES2SaltInput() {
		return $this->has(JWTParameter::P_P2S);
	}
	
	/**
	 * Get the PBES2 salt input parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return PBES2SaltInputParameter
	 */
	public function PBES2SaltInput() {
		return self::_checkType($this->get(JWTParameter::P_P2S), 
			PBES2SaltInputParameter::class);
	}
	
	/**
	 * Check whether the type parameter is present.
	 *
	 * @return bool
	 */
	public function hasType() {
		return $this->has(JWTParameter::P_TYP);
	}
	
	/**
	 * Get the type parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return TypeParameter
	 */
	public function type() {
		return self::_checkType($this->get(JWTParameter::P_TYP), 
			TypeParameter::class);
	}
	
	/**
	 * Check whether the X.509 certificate chain parameter is present.
	 *
	 * @return bool
	 */
	public function hasX509CertificateChain() {
		return $this->has(JWTParameter::P_X5C);
	}
	
	/**
	 * Get the X.509 certificate chain parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return X509CertificateChainParameter
	 */
	public function X509CertificateChain() {
		return self::_checkType($this->get(JWTParameter::P_X5C), 
			X509CertificateChainParameter::class);
	}
	
	/**
	 * Check whether the X.509 certificate SHA-1 thumbprint parameter is
	 * present.
	 *
	 * @return bool
	 */
	public function hasX509CertificateSHA1Thumbprint() {
		return $this->has(JWTParameter::P_X5T);
	}
	
	/**
	 * Get the X.509 certificate SHA-1 thumbprint parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return X509CertificateSHA1ThumbprintParameter
	 */
	public function X509CertificateSHA1Thumbprint() {
		return self::_checkType($this->get(JWTParameter::P_X5T), 
			X509CertificateSHA1ThumbprintParameter::class);
	}
	
	/**
	 * Check whether the X.509 certificate SHA-256 thumbprint parameter is
	 * present.
	 *
	 * @return bool
	 */
	public function hasX509CertificateSHA256Thumbprint() {
		return $this->has(JWTParameter::P_X5TS256);
	}
	
	/**
	 * Get the X.509 certificate SHA-256 thumbprint parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return X509CertificateSHA256ThumbprintParameter
	 */
	public function X509CertificateSHA256Thumbprint() {
		return self::_checkType($this->get(JWTParameter::P_X5TS256), 
			X509CertificateSHA256ThumbprintParameter::class);
	}
	
	/**
	 * Check whether the X.509 URL parameter is present.
	 *
	 * @return bool
	 */
	public function hasX509URL() {
		return $this->has(JWTParameter::P_X5U);
	}
	
	/**
	 * Get the X.509 URL parameter.
	 *
	 * @throws \UnexpectedValueException If the parameter has a wrong class
	 * @throws \LogicException If the parameter is not present
	 * @return X509URLParameter
	 */
	public function X509URL() {
		return self::_checkType($this->get(JWTParameter::P_X5U), 
			X509URLParameter::class);
	}
	
	/**
	 * Check that the parameter is an instance of the given class.
	 *
	 * @param JWTParameter $param Parameter
	 * @param string $cls Class name
	 * @throws \UnexpectedValueException
	 * @return JWTParameter
	 */
	private static function _checkType(JWTParameter $param, $cls) {
		if (!$param instanceof $cls) {
			throw new \UnexpectedValueException(
				"$cls expected, got " . get_class($param));
		}
		return $param;
	}
}
