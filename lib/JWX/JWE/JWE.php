<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE;

use Sop\JWX\JWE\CompressionAlgorithm\CompressionFactory;
use Sop\JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use Sop\JWX\JWE\KeyAlgorithm\KeyAlgorithmFactory;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\JOSE;
use Sop\JWX\Util\Base64;

/**
 * Class to represent JWE structure.
 *
 * @see https://tools.ietf.org/html/rfc7516#section-3
 */
class JWE
{
    /**
     * Protected header.
     *
     * @var Header
     */
    protected $_protectedHeader;

    /**
     * Encrypted key.
     *
     * @var string
     */
    protected $_encryptedKey;

    /**
     * Initialization vector.
     *
     * @var string
     */
    protected $_iv;

    /**
     * Additional authenticated data.
     *
     * @var null|string
     */
    protected $_aad;

    /**
     * Ciphertext.
     *
     * @var string
     */
    protected $_ciphertext;

    /**
     * Authentication tag.
     *
     * @var string
     */
    protected $_authenticationTag;

    /**
     * Constructor.
     *
     * @param Header      $protected_header JWE Protected Header
     * @param string      $encrypted_key    Encrypted key
     * @param string      $iv               Initialization vector
     * @param string      $ciphertext       Ciphertext
     * @param string      $auth_tag         Authentication tag
     * @param null|string $aad              Additional authenticated data
     */
    public function __construct(Header $protected_header, string $encrypted_key,
        string $iv, string $ciphertext, string $auth_tag, ?string $aad = null)
    {
        $this->_protectedHeader = $protected_header;
        $this->_encryptedKey = $encrypted_key;
        $this->_iv = $iv;
        $this->_aad = $aad;
        $this->_ciphertext = $ciphertext;
        $this->_authenticationTag = $auth_tag;
    }

    /**
     * Convert JWE to string.
     */
    public function __toString(): string
    {
        return $this->toCompact();
    }

    /**
     * Initialize from compact serialization.
     */
    public static function fromCompact(string $data): self
    {
        return self::fromParts(explode('.', $data));
    }

    /**
     * Initialize from parts of compact serialization.
     *
     * @throws \UnexpectedValueException
     */
    public static function fromParts(array $parts): self
    {
        if (5 !== count($parts)) {
            throw new \UnexpectedValueException(
                'Invalid JWE compact serialization.');
        }
        $header = Header::fromJSON(Base64::urlDecode($parts[0]));
        $encrypted_key = Base64::urlDecode($parts[1]);
        $iv = Base64::urlDecode($parts[2]);
        $ciphertext = Base64::urlDecode($parts[3]);
        $auth_tag = Base64::urlDecode($parts[4]);
        return new self($header, $encrypted_key, $iv, $ciphertext, $auth_tag);
    }

    /**
     * Initialize by encrypting the given payload.
     *
     * @param string                     $payload  Payload
     * @param KeyManagementAlgorithm     $key_algo Key management algorithm
     * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
     * @param null|CompressionAlgorithm  $zip_algo Optional compression algorithm
     * @param null|Header                $header   Optional desired header.
     *                                             Algorithm specific parameters are
     *                                             automatically added.
     * @param null|string                $cek      Optional content encryption key.
     *                                             Randomly enerated if not set.
     * @param null|string                $iv       Optional initialization vector.
     *                                             Randomly generated if not set.
     *
     * @throws \RuntimeException If encrypt fails
     */
    public static function encrypt(string $payload,
        KeyManagementAlgorithm $key_algo, ContentEncryptionAlgorithm $enc_algo,
        ?CompressionAlgorithm $zip_algo = null, ?Header $header = null,
        ?string $cek = null, ?string $iv = null): self
    {
        // if header was not given, initialize empty
        if (!isset($header)) {
            $header = new Header();
        }
        // generate random CEK
        if (!isset($cek)) {
            $cek = $key_algo->cekForEncryption($enc_algo->keySize());
        }
        // generate random IV
        if (!isset($iv)) {
            $iv = openssl_random_pseudo_bytes($enc_algo->ivSize());
        }
        // compress
        if (isset($zip_algo)) {
            $payload = $zip_algo->compress($payload);
            $header = $header->withParameters(...$zip_algo->headerParameters());
        }
        return self::_encryptContent($payload, $cek, $iv,
            $key_algo, $enc_algo, $header);
    }

    /**
     * Decrypt the content using explicit algorithms.
     *
     * @param KeyManagementAlgorithm     $key_algo Key management algorithm
     * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
     *
     * @throws \RuntimeException If decrypt fails
     *
     * @return string Plaintext payload
     */
    public function decrypt(KeyManagementAlgorithm $key_algo,
        ContentEncryptionAlgorithm $enc_algo): string
    {
        // check that key management algorithm matches
        if ($key_algo->algorithmParamValue() !== $this->algorithmName()) {
            throw new \UnexpectedValueException(
                'Invalid key management algorithm.');
        }
        // check that encryption algorithm matches
        if ($enc_algo->encryptionAlgorithmParamValue() !== $this->encryptionAlgorithmName()) {
            throw new \UnexpectedValueException('Invalid encryption algorithm.');
        }
        $header = $this->header();
        // decrypt content encryption key
        $cek = $key_algo->decrypt($this->_encryptedKey, $header);
        // decrypt payload
        $aad = Base64::urlEncode($this->_protectedHeader->toJSON());
        $payload = $enc_algo->decrypt($this->_ciphertext, $cek,
            $this->_iv, $aad, $this->_authenticationTag);
        // decompress
        if ($header->hasCompressionAlgorithm()) {
            $payload = CompressionFactory::algoByHeader($header)->decompress($payload);
        }
        return $payload;
    }

    /**
     * Decrypt content using given JWK.
     *
     * Key management and content encryption algorithms are determined from the
     * header.
     *
     * @param JWK $jwk JSON Web Key
     *
     * @throws \RuntimeException If algorithm initialization fails
     *
     * @return string Plaintext payload
     */
    public function decryptWithJWK(JWK $jwk): string
    {
        $header = $this->header();
        $key_algo = KeyManagementAlgorithm::fromJWK($jwk, $header);
        $enc_algo = EncryptionAlgorithmFactory::algoByHeader($header);
        return $this->decrypt($key_algo, $enc_algo);
    }

    /**
     * Decrypt content using a key from the given JWK set.
     *
     * Correct key shall be sought by the key ID indicated by the header.
     *
     * @param JWKSet $set Set of JSON Web Keys
     *
     * @throws \RuntimeException If algorithm initialization fails
     *
     * @return string Plaintext payload
     */
    public function decryptWithJWKSet(JWKSet $set): string
    {
        if (!count($set)) {
            throw new \RuntimeException('No keys.');
        }
        $header = $this->header();
        $factory = new KeyAlgorithmFactory($header);
        $key_algo = $factory->algoByKeys($set);
        $enc_algo = EncryptionAlgorithmFactory::algoByHeader($header);
        return $this->decrypt($key_algo, $enc_algo);
    }

    /**
     * Get JOSE header.
     */
    public function header(): JOSE
    {
        return new JOSE($this->_protectedHeader);
    }

    /**
     * Get the name of the key management algorithm.
     */
    public function algorithmName(): string
    {
        return $this->header()->algorithm()->value();
    }

    /**
     * Get the name of the encryption algorithm.
     */
    public function encryptionAlgorithmName(): string
    {
        return $this->header()->encryptionAlgorithm()->value();
    }

    /**
     * Get encrypted CEK.
     */
    public function encryptedKey(): string
    {
        return $this->_encryptedKey;
    }

    /**
     * Get initialization vector.
     */
    public function initializationVector(): string
    {
        return $this->_iv;
    }

    /**
     * Get ciphertext.
     */
    public function ciphertext(): string
    {
        return $this->_ciphertext;
    }

    /**
     * Get authentication tag.
     */
    public function authenticationTag(): string
    {
        return $this->_authenticationTag;
    }

    /**
     * Convert to compact serialization.
     */
    public function toCompact(): string
    {
        return Base64::urlEncode($this->_protectedHeader->toJSON()) . '.' .
             Base64::urlEncode($this->_encryptedKey) . '.' .
             Base64::urlEncode($this->_iv) . '.' .
             Base64::urlEncode($this->_ciphertext) . '.' .
             Base64::urlEncode($this->_authenticationTag);
    }

    /**
     * Encrypt content with explicit parameters.
     *
     * @param string                     $plaintext Plaintext content to encrypt
     * @param string                     $cek       Content encryption key
     * @param string                     $iv        Initialization vector
     * @param KeyManagementAlgorithm     $key_algo  Key management algorithm
     * @param ContentEncryptionAlgorithm $enc_algo  Content encryption algorithm
     * @param Header                     $header    Header
     *
     * @throws \UnexpectedValueException
     */
    private static function _encryptContent(string $plaintext, string $cek,
        string $iv, KeyManagementAlgorithm $key_algo,
        ContentEncryptionAlgorithm $enc_algo, Header $header): self
    {
        // check that content encryption key has correct size
        if (strlen($cek) !== $enc_algo->keySize()) {
            throw new \UnexpectedValueException('Invalid key size.');
        }
        // check that initialization vector has correct size
        if (strlen($iv) !== $enc_algo->ivSize()) {
            throw new \UnexpectedValueException('Invalid IV size.');
        }
        // add key and encryption algorithm parameters to the header
        $header = $header->withParameters(...$key_algo->headerParameters())
            ->withParameters(...$enc_algo->headerParameters());
        // encrypt the content encryption key
        $encrypted_key = $key_algo->encrypt($cek, $header);
        // sanity check that header wasn't unset via reference
        if (!$header instanceof Header) {
            throw new \RuntimeException('Broken key algorithm.');
        }
        // additional authenticated data
        $aad = Base64::urlEncode($header->toJSON());
        // encrypt
        [$ciphertext, $auth_tag] = $enc_algo->encrypt($plaintext, $cek, $iv, $aad);
        // TODO: should aad be passed
        return new self($header, $encrypted_key, $iv, $ciphertext, $auth_tag);
    }
}
