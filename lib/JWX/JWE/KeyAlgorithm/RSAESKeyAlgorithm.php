<?php

declare(strict_types = 1);

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing RSA based key encryption.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.2
 * @link https://tools.ietf.org/html/rfc7518#section-4.3
 */
abstract class RSAESKeyAlgorithm extends KeyManagementAlgorithm
{
    use RandomCEK;
    
    /**
     * Public key.
     *
     * @var RSAPublicKeyJWK $_publicKey
     */
    protected $_publicKey;
    
    /**
     * Private key.
     *
     * @var RSAPrivateKeyJWK|null $_privateKey
     */
    protected $_privateKey;
    
    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_ALGO_TO_CLASS = array(
        /* @formatter:off */
        JWA::ALGO_RSA1_5 => RSAESPKCS1Algorithm::class,
        JWA::ALGO_RSA_OAEP => RSAESOAEPAlgorithm::class
        /* @formatter:on */
    );
    
    /**
     * Get the padding scheme.
     *
     * @return int
     */
    abstract protected function _paddingScheme(): int;
    
    /**
     * Constructor.
     *
     * Use <code>fromPublicKey</code> or <code>fromPrivateKey</code> instead!
     *
     * @param RSAPublicKeyJWK $pub_key RSA public key
     * @param RSAPrivateKeyJWK $priv_key Optional RSA private key
     */
    protected function __construct(RSAPublicKeyJWK $pub_key,
        RSAPrivateKeyJWK $priv_key = null)
    {
        $this->_publicKey = $pub_key;
        $this->_privateKey = $priv_key;
    }
    
    /**
     *
     * @param JWK $jwk
     * @param Header $header
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromJWK(JWK $jwk, Header $header)
    {
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        if ($jwk->has(...RSAPrivateKeyJWK::MANAGED_PARAMS)) {
            return $cls::fromPrivateKey(RSAPrivateKeyJWK::fromJWK($jwk));
        }
        return $cls::fromPublicKey(RSAPublicKeyJWK::fromJWK($jwk));
    }
    
    /**
     * Initialize from a public key.
     *
     * @param RSAPublicKeyJWK $jwk
     * @return self
     */
    public static function fromPublicKey(RSAPublicKeyJWK $jwk): self
    {
        return new static($jwk);
    }
    
    /**
     * Initialize from a private key.
     *
     * @param RSAPrivateKeyJWK $jwk
     * @return self
     */
    public static function fromPrivateKey(RSAPrivateKeyJWK $jwk): self
    {
        return new static($jwk->publicKey(), $jwk);
    }
    
    /**
     * Get the public key.
     *
     * @return RSAPublicKeyJWK
     */
    public function publicKey(): RSAPublicKeyJWK
    {
        return $this->_publicKey;
    }
    
    /**
     * Check whether the private key is present.
     *
     * @return bool
     */
    public function hasPrivateKey(): bool
    {
        return isset($this->_privateKey);
    }
    
    /**
     * Get the private key.
     *
     * @throws \LogicException
     * @return RSAPrivateKeyJWK
     */
    public function privateKey(): RSAPrivateKeyJWK
    {
        if (!$this->hasPrivateKey()) {
            throw new \LogicException("Private key not set.");
        }
        return $this->_privateKey;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _encryptKey(string $key, Header &$header): string
    {
        $pubkey = openssl_pkey_get_public(
            $this->publicKey()
                ->toPEM()
                ->string());
        if (false === $pubkey) {
            throw new \RuntimeException(
                "openssl_pkey_get_public() failed: " .
                     $this->_getLastOpenSSLError());
        }
        $result = openssl_public_encrypt($key, $crypted, $pubkey,
            $this->_paddingScheme());
        if (!$result) {
            throw new \RuntimeException(
                "openssl_public_encrypt() failed: " .
                     $this->_getLastOpenSSLError());
        }
        return $crypted;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _decryptKey(string $ciphertext, Header $header): string
    {
        $privkey = openssl_pkey_get_private(
            $this->privateKey()
                ->toPEM()
                ->string());
        if (!$privkey) {
            throw new \RuntimeException(
                "openssl_pkey_get_private() failed: " .
                     $this->_getLastOpenSSLError());
        }
        $result = openssl_private_decrypt($ciphertext, $cek, $privkey,
            $this->_paddingScheme());
        if (!$result) {
            throw new \RuntimeException(
                "openssl_private_decrypt() failed: " .
                     $this->_getLastOpenSSLError());
        }
        return $cek;
    }
    
    /**
     * Get last OpenSSL error message.
     *
     * @return string|null
     */
    protected function _getLastOpenSSLError()
    {
        $msg = null;
        while (false !== ($err = openssl_error_string())) {
            $msg = $err;
        }
        return $msg;
    }
    
    /**
     *
     * @see \JWX\JWE\KeyManagementAlgorithm::headerParameters()
     * @return \JWX\JWT\Parameter\JWTParameter[]
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            array(AlgorithmParameter::fromAlgorithm($this)));
    }
}
