<?php

namespace JWX\JWK\RSA;

use CryptoUtil\ASN1\AlgorithmIdentifier\Crypto\RSAEncryptionAlgorithmIdentifier;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\ASN1\RSA\RSAPublicKey;
use CryptoUtil\PEM\PEM;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\ExponentParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\ModulusParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * Class representing RSA public key as a JWK.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link https://tools.ietf.org/html/rfc7518#section-6.3
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.1
 */
class RSAPublicKeyJWK extends JWK
{
	/**
	 * Parameter names managed by this class.
	 *
	 * @internal
	 *
	 * @var string[]
	 */
	const MANAGED_PARAMS = array(
		/* @formatter:off */
		RegisteredJWKParameter::PARAM_KEY_TYPE,
		RegisteredJWKParameter::PARAM_MODULUS,
		RegisteredJWKParameter::PARAM_EXPONENT
		/* @formatter:on */
	);
	
	/**
	 * Constructor
	 *
	 * @param JWKParameter ...$params
	 * @throws \UnexpectedValueException If missing required parameter
	 */
	public function __construct(JWKParameter ...$params) {
		parent::__construct(...$params);
		foreach (self::MANAGED_PARAMS as $name) {
			if (!$this->has($name)) {
				throw new \UnexpectedValueException("Missing '$name' parameter.");
			}
		}
		if ($this->keyTypeParameter()->value() != KeyTypeParameter::TYPE_RSA) {
			throw new \UnexpectedValueException("Invalid key type.");
		}
	}
	
	/**
	 * Initialize from RSAPublicKey.
	 *
	 * @param RSAPublicKey $pk
	 * @return self
	 */
	public static function fromRSAPublicKey(RSAPublicKey $pk) {
		$n = ModulusParameter::fromNumber($pk->modulus());
		$e = ExponentParameter::fromNumber($pk->publicExponent());
		$key_type = new KeyTypeParameter(KeyTypeParameter::TYPE_RSA);
		return new self($key_type, $n, $e);
	}
	
	/**
	 * Initialize from PEM.
	 *
	 * @param PEM $pem
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		return self::fromRSAPublicKey(RSAPublicKey::fromPEM($pem));
	}
	
	/**
	 * Convert JWK to PEM.
	 *
	 * @return PEM PUBLIC KEY
	 */
	public function toPEM() {
		$n = $this->modulusParameter()
			->number()
			->base10();
		$e = $this->exponentParameter()
			->number()
			->base10();
		$pk = new RSAPublicKey($n, $e);
		$pki = new PublicKeyInfo(new RSAEncryptionAlgorithmIdentifier(), 
			$pk->toDER());
		return $pki->toPEM();
	}
}
