<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\CryptoTypes\Asymmetric\EC\ECConversion;
use Sop\CryptoTypes\Signature\ECSignature;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\EC\ECPrivateKeyJWK;
use Sop\JWX\JWK\EC\ECPublicKeyJWK;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing elliptic curve signature computation.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.4
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
    const MAP_ALGO_TO_CLASS = [
        JWA::ALGO_ES256 => ES256Algorithm::class,
        JWA::ALGO_ES384 => ES384Algorithm::class,
        JWA::ALGO_ES512 => ES512Algorithm::class,
    ];

    /**
     * Signature size in bytes.
     *
     * @var int
     */
    private $_signatureSize;

    /**
     * Constructor.
     *
     * @param ECPublicKeyJWK  $pub_key
     * @param ECPrivateKeyJWK $priv_key
     */
    protected function __construct(ECPublicKeyJWK $pub_key,
        ?ECPrivateKeyJWK $priv_key = null)
    {
        $curve = $pub_key->curveParameter()->value();
        if ($this->_curveName() !== $curve) {
            throw new \InvalidArgumentException(
                'Key with ' . $this->_curveName() .
                     " curve expected, got {$curve}.");
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
     *
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
     *
     * @return self
     */
    public static function fromPrivateKey(ECPrivateKeyJWK $jwk): self
    {
        return new static($jwk->publicKey(), $jwk);
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromJWK(JWK $jwk, Header $header): SignatureAlgorithm
    {
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '{$alg}'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        if ($jwk->has(...ECPrivateKeyJWK::MANAGED_PARAMS)) {
            return $cls::fromPrivateKey(ECPrivateKeyJWK::fromJWK($jwk));
        }
        return $cls::fromPublicKey(ECPublicKeyJWK::fromJWK($jwk));
    }

    /**
     * {@inheritdoc}
     */
    public function computeSignature(string $data): string
    {
        // OpenSSL returns ECDSA signature as a DER encoded ECDSA-Sig-Value
        $der = parent::computeSignature($data);
        $sig = ECSignature::fromDER($der);
        $mlen = intval(floor($this->_signatureSize / 2));
        return ECConversion::numberToOctets($sig->r(), $mlen) .
             ECConversion::numberToOctets($sig->s(), $mlen);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \UnexpectedValueException If signature length is invalid
     */
    public function validateSignature(string $data, string $signature): bool
    {
        if (strlen($signature) !== $this->_signatureSize) {
            throw new \UnexpectedValueException('Invalid signature length.');
        }
        [$r_octets, $s_octets] = str_split($signature,
            intval(floor($this->_signatureSize / 2)));
        // convert signature to DER sequence for OpenSSL
        $r = ECConversion::octetsToNumber($r_octets);
        $s = ECConversion::octetsToNumber($s_octets);
        $sig = new ECSignature($r, $s);
        return parent::validateSignature($data, $sig->toDER());
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            [AlgorithmParameter::fromAlgorithm($this)]);
    }

    /**
     * Get the name of the curve used by this algorithm.
     *
     * @return string
     */
    abstract protected function _curveName(): string;
}
