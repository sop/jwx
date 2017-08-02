<?php

namespace JWX\JWK\Asymmetric;

use JWX\JWK\JWK;
use JWX\JWK\EC\ECPrivateKeyJWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;

/**
 * Base class for JWK private keys of an asymmetric key pairs.
 */
abstract class PrivateKeyJWK extends JWK
{
    /**
     * Get the public key component of the asymmetric key pair.
     *
     * @return PublicKeyJWK
     */
    abstract public function publicKey();
    
    /**
     * Convert private key to PEM.
     *
     * @return \Sop\CryptoEncoding\PEM
     */
    abstract public function toPEM();
    
    /**
     * Initialize from a PrivateKey object.
     *
     * @param PrivateKey $priv_key Private key
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromPrivateKey(PrivateKey $priv_key)
    {
        if ($priv_key instanceof RSAPrivateKey) {
            return RSAPrivateKeyJWK::fromRSAPrivateKey($priv_key);
        }
        if ($priv_key instanceof ECPrivateKey) {
            return ECPrivateKeyJWK::fromECPrivateKey($priv_key);
        }
        throw new \UnexpectedValueException("Unsupported private key.");
    }
    
    /**
     * Initialize from a PrivateKeyInfo object.
     *
     * @param PrivateKeyInfo $pki PrivateKeyInfo
     * @return self
     */
    public static function fromPrivateKeyInfo(PrivateKeyInfo $pki)
    {
        return self::fromPrivateKey($pki->privateKey());
    }
}
