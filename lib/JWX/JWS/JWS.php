<?php

declare(strict_types = 1);

namespace JWX\JWS;

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\JWKSet;
use JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\JWT\Parameter\CriticalParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\Util\Base64;

/**
 * Class to represent JWS structure.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-3
 */
class JWS
{
    /**
     * Protected header.
     *
     * @var Header $_protectedHeader
     */
    protected $_protectedHeader;
    
    /**
     * Payload.
     *
     * @var string $_payload
     */
    protected $_payload;
    
    /**
     * Input value for the signature computation.
     *
     * @var string $_signatureInput
     */
    protected $_signatureInput;
    
    /**
     * Signature.
     *
     * @var string $_signature
     */
    protected $_signature;
    
    /**
     * Constructor.
     *
     * @param Header $protected_header JWS Protected Header
     * @param string $payload JWS Payload
     * @param string $signature_input Input value for the signature computation
     * @param string $signature JWS Signature
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
     * Initialize from a compact serialization.
     *
     * @param string $data
     * @return self
     */
    public static function fromCompact(string $data): self
    {
        return self::fromParts(explode(".", $data));
    }
    
    /**
     * Initialize from the parts of a compact serialization.
     *
     * @param array $parts
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromParts(array $parts): self
    {
        if (count($parts) != 3) {
            throw new \UnexpectedValueException(
                "Invalid JWS compact serialization.");
        }
        $header = Header::fromJSON(Base64::urlDecode($parts[0]));
        $b64 = $header->hasB64Payload() ? $header->B64Payload()->value() : true;
        $payload = $b64 ? Base64::urlDecode($parts[1]) : $parts[1];
        $signature_input = $parts[0] . "." . $parts[1];
        $signature = Base64::urlDecode($parts[2]);
        return new self($header, $payload, $signature_input, $signature);
    }
    
    /**
     * Initialize by signing the payload with given algorithm.
     *
     * @param string $payload JWS Payload
     * @param SignatureAlgorithm $algo Signature algorithm
     * @param Header|null $header Desired header. Algorithm specific
     *        parameters are added automatically.
     * @throws \RuntimeException If signature computation fails
     * @return self
     */
    public static function sign(string $payload, SignatureAlgorithm $algo,
        Header $header = null): self
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
        return $this->header()
            ->algorithm()
            ->value();
    }
    
    /**
     * Check whether JWS is unsecured, that is, contains no signature.
     *
     * @return bool
     */
    public function isUnsecured(): bool
    {
        return $this->algorithmName() == JWA::ALGO_NONE;
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
     * Validate the signature using explicit algorithm.
     *
     * @param SignatureAlgorithm $algo
     * @throws \UnexpectedValueException If using different signature algorithm
     *         then specified by the header
     * @throws \RuntimeException If signature computation fails
     * @return bool True if signature is valid
     */
    public function validate(SignatureAlgorithm $algo): bool
    {
        if ($algo->algorithmParamValue() != $this->algorithmName()) {
            throw new \UnexpectedValueException("Invalid signature algorithm.");
        }
        return $algo->validateSignature($this->_signatureInput,
            $this->_signature);
    }
    
    /**
     * Validate the signature using the given JWK.
     *
     * Signature algorithm is determined from the header.
     *
     * @param JWK $jwk JSON Web Key
     * @throws \RuntimeException If algorithm initialization fails
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
     * @throws \RuntimeException If algorithm initialization fails
     * @return bool True if signature is valid
     */
    public function validateWithJWKSet(JWKSet $set): bool
    {
        if (!count($set)) {
            throw new \RuntimeException("No keys.");
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
        return Base64::urlEncode($this->_protectedHeader->toJSON()) . "." .
             $this->_encodedPayload() . "." .
             Base64::urlEncode($this->_signature);
    }
    
    /**
     * Convert to compact serialization with payload detached.
     *
     * @return string
     */
    public function toCompactDetached(): string
    {
        return Base64::urlEncode($this->_protectedHeader->toJSON()) . ".." .
             Base64::urlEncode($this->_signature);
    }
    
    /**
     * Generate input for the signature computation.
     *
     * @param string $payload Payload
     * @param Header $header Protected header
     * @return string
     */
    protected static function _generateSignatureInput(string $payload,
        Header $header): string
    {
        $b64 = $header->hasB64Payload() ? $header->B64Payload()->value() : true;
        $data = Base64::urlEncode($header->toJSON()) . ".";
        $data .= $b64 ? Base64::urlEncode($payload) : $payload;
        return $data;
    }
    
    /**
     * Convert JWS to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toCompact();
    }
}
