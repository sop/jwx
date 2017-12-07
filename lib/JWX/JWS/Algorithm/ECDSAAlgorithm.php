<?php

declare(strict_types = 1);

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\EC\ECPrivateKeyJWK;
use JWX\JWK\EC\ECPublicKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use Sop\CryptoTypes\Asymmetric\EC\ECConversion;
use Sop\CryptoTypes\Signature\ECSignature;

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
    const MAP_ALGO_TO_CLASS = array(
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
    abstract protected function _curveName(): string;
    
    /**
     * Constructor.
     *
     * @param ECPublicKeyJWK $pub_key
     * @param ECPrivateKeyJWK $priv_key
     */
    protected function __construct(ECPublicKeyJWK $pub_key,
        ECPrivateKeyJWK $priv_key = null)
    {
        $curve = $pub_key->curveParameter()->value();
        if ($this->_curveName() != $curve) {
            throw new \InvalidArgumentException(
                "Key with " . $this->_curveName() .
                     " curve expected, got $curve.");
        }
        $this->_publicKey = $pub_key;
        $this->_privateKey = $priv_key;
        $key_size = $pub_key->curveParameter()->keySizeBits();
        $this->_signatureSize = intval(ceil($key_size / 8) * 2);
    }
    
    /**
     * Initialize from a public key.
     *
     * @param ECPublicKeyJWK $jwk
     * @return self
     */
    public static function fromPublicKey(ECPublicKeyJWK $jwk): self
    {
        return new static($jwk);
    }
    
    /**
     * Initialize from a private key.
     *
     * @param ECPrivateKeyJWK $jwk
     * @return self
     */
    public static function fromPrivateKey(ECPrivateKeyJWK $jwk): self
    {
        return new static($jwk->publicKey(), $jwk);
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public static function fromJWK(JWK $jwk, Header $header): self
    {
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        if ($jwk->has(...ECPrivateKeyJWK::MANAGED_PARAMS)) {
            return $cls::fromPrivateKey(ECPrivateKeyJWK::fromJWK($jwk));
        }
        return $cls::fromPublicKey(ECPublicKeyJWK::fromJWK($jwk));
    }
    
    /**
     *
     * @see \JWX\JWS\Algorithm\OpenSSLSignatureAlgorithm::computeSignature()
     * @return string
     */
    public function computeSignature(string $data): string
    {
        // OpenSSL returns ECDSA signature as a DER encoded ECDSA-Sig-Value
        $der = parent::computeSignature($data);
        $sig = ECSignature::fromDER($der);
        $mlen = intval(floor($this->_signatureSize / 2));
        $signature = ECConversion::numberToOctets($sig->r(), $mlen) .
             ECConversion::numberToOctets($sig->s(), $mlen);
        return $signature;
    }
    
    /**
     *
     * @see \JWX\JWS\Algorithm\OpenSSLSignatureAlgorithm::validateSignature()
     * @return bool
     */
    public function validateSignature(string $data, string $signature): bool
    {
        if (strlen($signature) != $this->_signatureSize) {
            throw new \UnexpectedValueException("Invalid signature length.");
        }
        list($r_octets, $s_octets) = str_split($signature,
            intval(floor($this->_signatureSize / 2)));
        // convert signature to DER sequence for OpenSSL
        $r = ECConversion::octetsToNumber($r_octets);
        $s = ECConversion::octetsToNumber($s_octets);
        $sig = new ECSignature($r, $s);
        return parent::validateSignature($data, $sig->toDER());
    }
    
    /**
     *
     * @see \JWX\JWS\SignatureAlgorithm::headerParameters()
     * @return \JWX\JWT\Parameter\JWTParameter[]
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            array(AlgorithmParameter::fromAlgorithm($this)));
    }
}
