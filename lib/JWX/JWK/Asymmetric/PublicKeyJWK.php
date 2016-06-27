<?php

namespace JWX\JWK\Asymmetric;

use CryptoUtil\ASN1\EC\ECPublicKey;
use CryptoUtil\ASN1\PublicKey;
use CryptoUtil\ASN1\PublicKeyInfo;
use CryptoUtil\ASN1\RSA\RSAPublicKey;
use CryptoUtil\PEM\PEM;
use JWX\JWK\EC\ECPublicKeyJWK;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;


/**
 * Base class for JWK public keys of an asymmetric key pairs.
 */
abstract class PublicKeyJWK extends JWK
{
	/**
	 * Convert public key to PEM.
	 *
	 * @return PEM
	 */
	abstract public function toPEM();
	
	/**
	 * Initialize from a PublicKey object.
	 *
	 * @param PublicKey $pub_key Public key
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromPublicKey(PublicKey $pub_key) {
		if ($pub_key instanceof RSAPublicKey) {
			return RSAPublicKeyJWK::fromRSAPublicKey($pub_key);
		}
		if ($pub_key instanceof ECPublicKey) {
			return ECPublicKeyJWK::fromECPublicKey($pub_key);
		}
		throw new \UnexpectedValueException("Unsupported public key.");
	}
	
	/**
	 * Initialize from a PublicKeyInfo object.
	 *
	 * @param PublicKeyInfo $pki Public key info
	 * @return self
	 */
	public static function fromPublicKeyInfo(PublicKeyInfo $pki) {
		return self::fromPublicKey($pki->publicKey());
	}
}
