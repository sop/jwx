<?php

namespace JWX\JWS\Algorithm;

use CryptoUtil\ASN1\EC\ECDSASigValue;
use CryptoUtil\Conversion\ECConversion;
use JWX\JWA\JWA;
use JWX\JWK\EC\ECPrivateKeyJWK;
use JWX\JWK\EC\ECPublicKeyJWK;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\CurveParameter;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;


/**
 * Base class for algorithms implementing elliptic curve signature computation.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.4
 */
abstract class ECDSAAlgorithm extends OpenSSLSignatureAlgorithm
{
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_NAME_TO_CLASS = array(
		/* @formatter:off */
		JWA::ALGO_ES256 => ES256Algorithm::class,
		JWA::ALGO_ES384 => ES384Algorithm::class,
		JWA::ALGO_ES512 => ES512Algorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Signature size in bytes.
	 *
	 * @var int
	 */
	private $_signatureSize;
	
	/**
	 * Get the name of the curve used by this algorithm.
	 *
	 * @return string
	 */
	abstract protected function _curveName();
	
	/**
	 * Constructor
	 *
	 * @param ECPublicKeyJWK $pub_key
	 * @param ECPrivateKeyJWK $priv_key
	 */
	protected function __construct(ECPublicKeyJWK $pub_key, 
			ECPrivateKeyJWK $priv_key = null) {
		$curve = $pub_key->curveParameter()->value();
		if ($this->_curveName() != $curve) {
			throw new \InvalidArgumentException(
				"Key with " . $this->_curveName() .
					 " curve expected, got $curve.");
		}
		$this->_publicKey = $pub_key;
		$this->_privateKey = $priv_key;
		$key_size = $pub_key->curveParameter()->keySizeBits();
		$this->_signatureSize = ceil($key_size / 8) * 2;
	}
	
	/**
	 * Initialize from a public key.
	 *
	 * @param ECPublicKeyJWK $jwk
	 * @return self
	 */
	public static function fromPublicKey(ECPublicKeyJWK $jwk) {
		return new static($jwk);
	}
	
	/**
	 * Initialize from a private key.
	 *
	 * @param ECPrivateKeyJWK $jwk
	 * @return self
	 */
	public static function fromPrivateKey(ECPrivateKeyJWK $jwk) {
		return new static($jwk->publicKey(), $jwk);
	}
	
	/**
	 * Initialize from a JWK.
	 *
	 * If algorithm is not specified, look from JWK.
	 *
	 * @param JWK $jwk
	 * @param string|null $alg Optional algorithm name
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromJWK(JWK $jwk, $alg = null) {
		// if algorithm is not explicitly given, consult JWK
		if (!isset($alg)) {
			if (!$jwk->hasAlgorithmParameter()) {
				throw new \UnexpectedValueException(
					"Missing algorithm parameter.");
			}
			$alg = $jwk->algorithmParameter()->value();
		}
		if (!array_key_exists($alg, self::MAP_NAME_TO_CLASS)) {
			throw new \UnexpectedValueException(
				"Algorithm '$alg' not supported.");
		}
		$cls = self::MAP_NAME_TO_CLASS[$alg];
		$params = ECPrivateKeyJWK::MANAGED_PARAMS;
		if ($jwk->has(...$params)) {
			return $cls::fromPrivateKey(ECPrivateKeyJWK::fromJWK($jwk));
		}
		$params = ECPublicKeyJWK::MANAGED_PARAMS;
		if ($jwk->has(...$params)) {
			return $cls::fromPublicKey(ECPublicKeyJWK::fromJWK($jwk));
		}
		throw new \UnexpectedValueException("Not an EC key.");
	}
	
	/**
	 *
	 * @see \JWX\JWS\Algorithm\OpenSSLSignatureAlgorithm::computeSignature()
	 * @return string
	 */
	public function computeSignature($data) {
		// OpenSSL returns ECDSA signature as a DER encoded ECDSA-Sig-Value
		$der = parent::computeSignature($data);
		$sig = ECDSASigValue::fromDER($der);
		$mlen = floor($this->_signatureSize / 2);
		$signature = ECConversion::numberToOctets($sig->r(), $mlen) .
			 ECConversion::numberToOctets($sig->s(), $mlen);
		return $signature;
	}
	
	/**
	 *
	 * @see \JWX\JWS\Algorithm\OpenSSLSignatureAlgorithm::validateSignature()
	 * @return bool
	 */
	public function validateSignature($data, $signature) {
		if (strlen($signature) != $this->_signatureSize) {
			throw new \UnexpectedValueException("Invalid signature length.");
		}
		list($r_octets, $s_octets) = str_split($signature, 
			floor($this->_signatureSize / 2));
		// convert signature to DER sequence for OpenSSL
		$r = ECConversion::octetsToNumber($r_octets);
		$s = ECConversion::octetsToNumber($s_octets);
		$sig = new ECDSASigValue($r, $s);
		return parent::validateSignature($data, $sig->toDER());
	}
	
	/**
	 *
	 * @see \JWX\JWT\Header\HeaderParameters::headerParameters()
	 * @return JWTParameter[]
	 */
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}
