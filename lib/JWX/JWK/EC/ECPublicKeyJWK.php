<?php

namespace JWX\JWK\EC;

use CryptoUtil\ASN1\EC\ECPublicKey;
use CryptoUtil\Conversion\ECConversion;
use CryptoUtil\PEM\PEM;
use JWX\JWK\Feature\AsymmetricPublicKey;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\CurveParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\XCoordinateParameter;
use JWX\JWK\Parameter\YCoordinateParameter;


/**
 * Class representing elliptic curve public key as a JWK.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link https://tools.ietf.org/html/rfc7518#section-6.2
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.1
 */
class ECPublicKeyJWK extends JWK implements AsymmetricPublicKey
{
	/**
	 * Parameter names managed by this class.
	 *
	 * @var string[]
	 */
	const MANAGED_PARAMS = array(
		/* @formatter:off */
		RegisteredJWKParameter::PARAM_KEY_TYPE, 
		RegisteredJWKParameter::PARAM_CURVE, 
		RegisteredJWKParameter::PARAM_X_COORDINATE
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
		if ($this->keyTypeParameter()->value() != KeyTypeParameter::TYPE_EC) {
			throw new \UnexpectedValueException("Invalid key type.");
		}
	}
	
	/**
	 * Initialize from ECPublicKey.
	 *
	 * @param ECPublicKey $pk
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromECPublicKey(ECPublicKey $pk) {
		if (!$pk->hasNamedCurve()) {
			throw new \UnexpectedValueException("No curve name.");
		}
		$curve = CurveParameter::fromOID($pk->namedCurve());
		list($x, $y) = $pk->curvePointOctets();
		$xcoord = XCoordinateParameter::fromString($x);
		$ycoord = YCoordinateParameter::fromString($y);
		$key_type = new KeyTypeParameter(KeyTypeParameter::TYPE_EC);
		return new self($key_type, $curve, $xcoord, $ycoord);
	}
	
	/**
	 * Initialize from PEM.
	 *
	 * @param PEM $pem
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		return self::fromECPublicKey(ECPublicKey::fromPEM($pem));
	}
	
	/**
	 * Convert EC public key to PEM.
	 *
	 * @return PEM
	 */
	public function toPEM() {
		$curve_oid = CurveParameter::nameToOID($this->curveParameter()->value());
		$x = ECConversion::octetsToNumber(
			$this->XCoordinateParameter()->coordinateOctets());
		$y = ECConversion::octetsToNumber(
			$this->YCoordinateParameter()->coordinateOctets());
		$ec = ECPublicKey::fromCoordinates($x, $y, $curve_oid);
		return $ec->publicKeyInfo()->toPEM();
	}
}
