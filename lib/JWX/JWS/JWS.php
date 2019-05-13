<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\JOSE;
use Sop\JWX\JWT\Parameter\CriticalParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\Util\Base64;

/**
 * Class to represent JWS structure.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-3
 */
class JWS
{
    /**
     * Protected header.
     *
     * @var Header
     */
    protected $_protectedHeader;

    /**
     * Payload.
     *
     * @var string
     */
    protected $_payload;

    /**
     * Input value for the signature computation.
     *
     * @var string
     */
    protected $_signatureInput;

    /**
     * Signature.
     *
     * @var string
     */
    protected $_signature;

    /**
     * Constructor.
     *
     * @param Header $protected_header JWS Protected Header
     * @param string $payload          JWS Payload
     * @param string $signature_input  Input value for the signature computation
     * @param string $signature        JWS Signature
     */
    protected function __construct(Header $protected_header, string $payload,
        string $signature_input, string $signature)
    {
        $this->_protectedHeader = $protected_header;
        $this->_payload = $payload;
        $this->_signatureInput = $signature_input;
        $this->_signature = $signature;
    }

    /**
     * Convert JWS to string.
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->toCompact();
    }

    /**
     * Initialize from a compact serialization.
     *
     * @param string $data
     *
     * @return self
     */
    public static function fromCompact(string $data): self
    {
        return self::fromParts(explode('.', $data));
    }

    /**
     * Initialize from the parts of a compact serialization.
     *
     * @param array $parts
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromParts(array $parts): self
    {
        if (3 !== count($parts)) {
            throw new \UnexpectedValueException(
                'Invalid JWS compact serialization.');
        }
        $header = Header::fromJSON(Base64::urlDecode($parts[0]));
        $b64 = $header->hasB64Payload() ? $header->B64Payload()->value() : true;
        $payload = $b64 ? Base64::urlDecode($parts[1]) : $parts[1];
        $signature_input = $parts[0] . '.' . $parts[1];
        $signature = Base64::urlDecode($parts[2]);
        return new self($header, $payload, $signature_input, $signature);
    }

    /**
     * Initialize by signing the payload with given algorithm.
     *
     * @param string             $payload JWS Payload
     * @param SignatureAlgorithm $algo    Signature algorithm
     * @param null|Header        $header  Desired header. Algorithm specific
     *                                    parameters are added automatically.
     *
     * @throws \RuntimeException If signature computation fails
     *
     * @return self
     */
    public static function sign(string $payload, SignatureAlgorithm $algo,
        ?Header $header = null): self
    {
        if (!isset($header)) {
            $header = new Header();
        }
        $header = $header->withParameters(...$algo->headerParameters());
        // ensure that if b64 parameter is used, it's marked critical
        if ($header->hasB64Payload()) {
            if (!$header->hasCritical()) {
                $crit = new CriticalParameter(JWTParameter::P_B64);
            } else {
                $crit = $header->critical()->withParamName(JWTParameter::P_B64);
            }
            $header = $header->withParameters($crit);
        }
        $signature_input = self::_generateSignatureInput($payload, $header);
        $signature = $algo->computeSignature($signature_input);
        return new self($header, $payload, $signature_input, $signature);
    }

    /**
     * Get JOSE header.
     *
     * @return JOSE
     */
    public function header(): JOSE
    {
        return new JOSE($this->_protectedHeader);
    }

    /**
     * Get the signature algorithm name.
     *
     * @return string
     */
    public function algorithmName(): string
    {
        return $this->header()->algorithm()->value();
    }

    /**
     * Check whether JWS is unsecured, that is, contains no signature.
     *
     * @return bool
     */
    public function isUnsecured(): bool
    {
        return JWA::ALGO_NONE === $this->algorithmName();
    }

    /**
     * Get the payload.
     *
     * @return string
     */
    public function payload(): string
    {
        return $this->_payload;
    }

    /**
     * Get the signature.
     *
     * @return string
     */
    public function signature(): string
    {
        return $this->_signature;
    }

    /**
     * Validate the signature using explicit algorithm.
     *
     * @param SignatureAlgorithm $algo
     *
     * @throws \UnexpectedValueException If using different signature algorithm
     *                                   then specified by the header
     * @throws \RuntimeException         If signature computation fails
     *
     * @return bool True if signature is valid
     */
    public function validate(SignatureAlgorithm $algo): bool
    {
        if ($algo->algorithmParamValue() !== $this->algorithmName()) {
            throw new \UnexpectedValueException('Invalid signature algorithm.');
        }
        return $algo->validateSignature($this->_signatureInput, $this->_signature);
    }

    /**
     * Validate the signature using the given JWK.
     *
     * Signature algorithm is determined from the header.
     *
     * @param JWK $jwk JSON Web Key
     *
     * @throws \RuntimeException If algorithm initialization fails
     *
     * @return bool True if signature is valid
     */
    public function validateWithJWK(JWK $jwk): bool
    {
        $algo = SignatureAlgorithm::fromJWK($jwk, $this->header());
        return $this->validate($algo);
    }

    /**
     * Validate the signature using a key from the given JWK set.
     *
     * Correct key shall be sought by the key ID indicated by the header.
     *
     * @param JWKSet $set Set of JSON Web Keys
     *
     * @throws \RuntimeException If algorithm initialization fails
     *
     * @return bool True if signature is valid
     */
    public function validateWithJWKSet(JWKSet $set): bool
    {
        if (!count($set)) {
            throw new \RuntimeException('No keys.');
        }
        $factory = new SignatureAlgorithmFactory($this->header());
        $algo = $factory->algoByKeys($set);
        return $this->validate($algo);
    }

    /**
     * Convert to compact serialization.
     *
     * @return string
     */
    public function toCompact(): string
    {
        return Base64::urlEncode($this->_protectedHeader->toJSON()) . '.' .
             $this->_encodedPayload() . '.' .
             Base64::urlEncode($this->_signature);
    }

    /**
     * Convert to compact serialization with payload detached.
     *
     * @return string
     */
    public function toCompactDetached(): string
    {
        return Base64::urlEncode($this->_protectedHeader->toJSON()) . '..' .
             Base64::urlEncode($this->_signature);
    }

    /**
     * Get the payload encoded for serialization.
     *
     * @return string
     */
    protected function _encodedPayload(): string
    {
        $b64 = true;
        if ($this->_protectedHeader->hasB64Payload()) {
            $b64 = $this->_protectedHeader->B64Payload()->value();
        }
        return $b64 ? Base64::urlEncode($this->_payload) : $this->_payload;
    }

    /**
     * Generate input for the signature computation.
     *
     * @param string $payload Payload
     * @param Header $header  Protected header
     *
     * @return string
     */
    protected static function _generateSignatureInput(string $payload,
        Header $header): string
    {
        $b64 = $header->hasB64Payload() ? $header->B64Payload()->value() : true;
        $data = Base64::urlEncode($header->toJSON()) . '.';
        $data .= $b64 ? Base64::urlEncode($payload) : $payload;
        return $data;
    }
}
