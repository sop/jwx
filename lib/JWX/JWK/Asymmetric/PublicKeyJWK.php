<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Asymmetric;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use Sop\JWX\JWK\EC\ECPublicKeyJWK;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\RSA\RSAPublicKeyJWK;

/**
 * Base class for JWK public keys of an asymmetric key pairs.
 */
abstract class PublicKeyJWK extends JWK
{
    /**
     * Convert public key to PEM.
     */
    abstract public function toPEM(): PEM;

    /**
     * Initialize from a PublicKey object.
     *
     * @param PublicKey $pub_key Public key
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromPublicKey(PublicKey $pub_key): PublicKeyJWK
    {
        if ($pub_key instanceof RSAPublicKey) {
            return RSAPublicKeyJWK::fromRSAPublicKey($pub_key);
        }
        if ($pub_key instanceof ECPublicKey) {
            return ECPublicKeyJWK::fromECPublicKey($pub_key);
        }
        throw new \UnexpectedValueException('Unsupported public key.');
    }

    /**
     * Initialize from a PublicKeyInfo object.
     *
     * @param PublicKeyInfo $pki Public key info
     *
     * @return self
     */
    public static function fromPublicKeyInfo(PublicKeyInfo $pki): PublicKeyJWK
    {
        return self::fromPublicKey($pki->publicKey());
    }
}
