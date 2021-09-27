<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Asymmetric;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\JWX\JWK\EC\ECPrivateKeyJWK;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\RSA\RSAPrivateKeyJWK;

/**
 * Base class for JWK private keys of an asymmetric key pairs.
 */
abstract class PrivateKeyJWK extends JWK
{
    /**
     * Get the public key component of the asymmetric key pair.
     */
    abstract public function publicKey(): PublicKeyJWK;

    /**
     * Convert private key to PEM.
     */
    abstract public function toPEM(): PEM;

    /**
     * Initialize from a PrivateKey object.
     *
     * @param PrivateKey $priv_key Private key
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromPrivateKey(PrivateKey $priv_key): PrivateKeyJWK
    {
        if ($priv_key instanceof RSAPrivateKey) {
            return RSAPrivateKeyJWK::fromRSAPrivateKey($priv_key);
        }
        if ($priv_key instanceof ECPrivateKey) {
            return ECPrivateKeyJWK::fromECPrivateKey($priv_key);
        }
        throw new \UnexpectedValueException('Unsupported private key.');
    }

    /**
     * Initialize from a PrivateKeyInfo object.
     *
     * @param PrivateKeyInfo $pki PrivateKeyInfo
     *
     * @return self
     */
    public static function fromPrivateKeyInfo(PrivateKeyInfo $pki): PrivateKeyJWK
    {
        return self::fromPrivateKey($pki->privateKey());
    }
}
