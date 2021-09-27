<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\EC;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECConversion;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\JWX\JWK\Asymmetric\PrivateKeyJWK;
use Sop\JWX\JWK\Asymmetric\PublicKeyJWK;
use Sop\JWX\JWK\Parameter\CurveParameter;
use Sop\JWX\JWK\Parameter\ECCPrivateKeyParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\XCoordinateParameter;
use Sop\JWX\JWK\Parameter\YCoordinateParameter;

/**
 * Class representing elliptic curve private key as a JWK.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4
 * @see https://tools.ietf.org/html/rfc7518#section-6.2
 * @see https://tools.ietf.org/html/rfc7518#section-6.2.2
 */
class ECPrivateKeyJWK extends PrivateKeyJWK
{
    /**
     * Parameter names managed by this class.
     *
     * @internal
     *
     * @var string[]
     */
    public const MANAGED_PARAMS = [
        JWKParameter::PARAM_KEY_TYPE,
        JWKParameter::PARAM_CURVE,
        JWKParameter::PARAM_X_COORDINATE,
        JWKParameter::PARAM_ECC_PRIVATE_KEY,
    ];

    /**
     * Constructor.
     *
     * @param JWKParameter ...$params
     *
     * @throws \UnexpectedValueException If missing required parameter
     */
    public function __construct(JWKParameter ...$params)
    {
        parent::__construct(...$params);
        foreach (self::MANAGED_PARAMS as $name) {
            if (!$this->has($name)) {
                throw new \UnexpectedValueException("Missing '{$name}' parameter.");
            }
        }
        if (KeyTypeParameter::TYPE_EC !== $this->keyTypeParameter()->value()) {
            throw new \UnexpectedValueException('Invalid key type.');
        }
        // cast ECC private key parameter to correct class
        $key = JWKParameter::PARAM_ECC_PRIVATE_KEY;
        $this->_parameters[$key] = new ECCPrivateKeyParameter(
            $this->_parameters[$key]->value());
    }

    /**
     * Initialize from ECPrivateKey.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromECPrivateKey(ECPrivateKey $pk): self
    {
        if (!$pk->hasNamedCurve()) {
            throw new \UnexpectedValueException('No curve name.');
        }
        $curve = CurveParameter::fromOID($pk->namedCurve());
        $pubkey = $pk->publicKey();
        [$x, $y] = $pubkey->curvePointOctets();
        $xcoord = XCoordinateParameter::fromString($x);
        $ycoord = YCoordinateParameter::fromString($y);
        $priv = ECCPrivateKeyParameter::fromString($pk->privateKeyOctets());
        $key_type = new KeyTypeParameter(KeyTypeParameter::TYPE_EC);
        return new self($key_type, $curve, $xcoord, $ycoord, $priv);
    }

    /**
     * Initialize from PEM.
     */
    public static function fromPEM(PEM $pem): self
    {
        return self::fromECPrivateKey(ECPrivateKey::fromPEM($pem));
    }

    /**
     * Get the public key component of the EC private key.
     *
     * @return ECPublicKeyJWK
     */
    public function publicKey(): PublicKeyJWK
    {
        $kty = $this->keyTypeParameter();
        $curve = $this->curveParameter();
        $xcoord = $this->XCoordinateParameter();
        $ycoord = $this->YCoordinateParameter();
        return new ECPublicKeyJWK($kty, $curve, $xcoord, $ycoord);
    }

    /**
     * Convert EC private key to PEM.
     */
    public function toPEM(): PEM
    {
        $curve_oid = CurveParameter::nameToOID($this->curveParameter()->value());
        $x = ECConversion::octetsToNumber(
            $this->XCoordinateParameter()->coordinateOctets());
        $y = ECConversion::octetsToNumber(
            $this->YCoordinateParameter()->coordinateOctets());
        $pubkey = ECPublicKey::fromCoordinates($x, $y, $curve_oid);
        $priv = $this->ECCPrivateKeyParameter()->privateKeyOctets();
        $ec = new ECPrivateKey($priv, $curve_oid, $pubkey->ECPoint());
        return $ec->privateKeyInfo()->toPEM();
    }
}
