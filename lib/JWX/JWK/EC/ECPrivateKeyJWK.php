<?php

namespace JWX\JWK\EC;

use CryptoUtil\ASN1\EC\ECPrivateKey;
use CryptoUtil\ASN1\EC\ECPublicKey;
use CryptoUtil\Conversion\ECConversion;
use CryptoUtil\PEM\PEM;
use JWX\JWK\Feature\AsymmetricPrivateKey;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\CurveParameter;
use JWX\JWK\Parameter\ECCPrivateKeyParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\XCoordinateParameter;
use JWX\JWK\Parameter\YCoordinateParameter;


/**
 * Class representing elliptic curve private key as a JWK.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link https://tools.ietf.org/html/rfc7518#section-6.2
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.2
 */
class ECPrivateKeyJWK extends JWK implements AsymmetricPrivateKey
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
		RegisteredJWKParameter::PARAM_CURVE, 
		RegisteredJWKParameter::PARAM_X_COORDINATE, 
		RegisteredJWKParameter::PARAM_ECC_PRIVATE_KEY
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
		// cast ECC private key parameter to correct class
		$key = RegisteredJWKParameter::PARAM_ECC_PRIVATE_KEY;
		$this->_parameters[$key] = new ECCPrivateKeyParameter(
			$this->_parameters[$key]->value());
	}
	
	/**
	 * Initialize from ECPrivateKey.
	 *
	 * @param ECPrivateKey $pk
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromECPrivateKey(ECPrivateKey $pk) {
		if (!$pk->hasNamedCurve()) {
			throw new \UnexpectedValueException("No curve name.");
		}
		$curve = CurveParameter::fromOID($pk->namedCurve());
		$pubkey = $pk->publicKey();
		list($x, $y) = $pubkey->curvePointOctets();
		$xcoord = XCoordinateParameter::fromString($x);
		$ycoord = YCoordinateParameter::fromString($y);
		$priv = ECCPrivateKeyParameter::fromString($pk->privateKeyOctets());
		$key_type = new KeyTypeParameter(KeyTypeParameter::TYPE_EC);
		return new self($key_type, $curve, $xcoord, $ycoord, $priv);
	}
	
	/**
	 * Initialize from PEM.
	 *
	 * @param PEM $pem
	 * @return self
	 */
	public static function fromPEM(PEM $pem) {
		return self::fromECPrivateKey(ECPrivateKey::fromPEM($pem));
	}
	
	/**
	 * Get the public key component of the EC private key.
	 *
	 * @return ECPublicKeyJWK
	 */
	public function publicKey() {
		$kty = $this->keyTypeParameter();
		$curve = $this->curveParameter();
		$xcoord = $this->XCoordinateParameter();
		$ycoord = $this->YCoordinateParameter();
		return new ECPublicKeyJWK($kty, $curve, $xcoord, $ycoord);
	}
	
	/**
	 * Convert EC private key to PEM.
	 *
	 * @return PEM
	 */
	public function toPEM() {
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
