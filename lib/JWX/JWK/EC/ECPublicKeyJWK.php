<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\EC;

use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECConversion;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\JWX\JWK\Asymmetric\PublicKeyJWK;
use Sop\JWX\JWK\Parameter\CurveParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\XCoordinateParameter;
use Sop\JWX\JWK\Parameter\YCoordinateParameter;

/**
 * Class representing elliptic curve public key as a JWK.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4
 * @see https://tools.ietf.org/html/rfc7518#section-6.2
 * @see https://tools.ietf.org/html/rfc7518#section-6.2.1
 */
class ECPublicKeyJWK extends PublicKeyJWK
{
    /**
     * Parameter names managed by this class.
     *
     * @var string[]
     */
    const MANAGED_PARAMS = [
        JWKParameter::PARAM_KEY_TYPE,
        JWKParameter::PARAM_CURVE,
        JWKParameter::PARAM_X_COORDINATE,
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
                throw new \UnexpectedValueException(
                    "Missing '{$name}' parameter.");
            }
        }
        if (KeyTypeParameter::TYPE_EC !== $this->keyTypeParameter()->value()) {
            throw new \UnexpectedValueException('Invalid key type.');
        }
    }

    /**
     * Initialize from ECPublicKey.
     *
     * @param ECPublicKey $pk
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromECPublicKey(ECPublicKey $pk): self
    {
        if (!$pk->hasNamedCurve()) {
            throw new \UnexpectedValueException('No curve name.');
        }
        $curve = CurveParameter::fromOID($pk->namedCurve());
        [$x, $y] = $pk->curvePointOctets();
        $xcoord = XCoordinateParameter::fromString($x);
        $ycoord = YCoordinateParameter::fromString($y);
        $key_type = new KeyTypeParameter(KeyTypeParameter::TYPE_EC);
        return new self($key_type, $curve, $xcoord, $ycoord);
    }

    /**
     * Initialize from PEM.
     *
     * @param PEM $pem
     *
     * @return self
     */
    public static function fromPEM(PEM $pem): self
    {
        return self::fromECPublicKey(ECPublicKey::fromPEM($pem));
    }

    /**
     * Convert EC public key to PEM.
     *
     * @return PEM
     */
    public function toPEM(): PEM
    {
        $curve_oid = CurveParameter::nameToOID($this->curveParameter()->value());
        $x = ECConversion::octetsToNumber(
            $this->XCoordinateParameter()->coordinateOctets());
        $y = ECConversion::octetsToNumber(
            $this->YCoordinateParameter()->coordinateOctets());
        $ec = ECPublicKey::fromCoordinates($x, $y, $curve_oid);
        return $ec->publicKeyInfo()->toPEM();
    }
}
