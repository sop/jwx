<?php

namespace JWX\JWS;

use JWX\JWK\JWK;
use JWX\JWK\JWKSet;
use JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\JWT\Parameter\CriticalParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
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
	 * Constructor
	 *
	 * @param Header $protected_header JWS Protected Header
	 * @param string $payload JWS Payload
	 * @param string $signature_input Input value for the signature computation
	 * @param string $signature JWS Signature
	 */
	protected function __construct(Header $protected_header, $payload, 
			$signature_input, $signature) {
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
	public static function fromCompact($data) {
		return self::fromParts(explode(".", $data));
	}
	
	/**
	 * Initialize from the parts of a compact serialization.
	 *
	 * @param array $parts
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromParts(array $parts) {
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
	public static function sign($payload, SignatureAlgorithm $algo, 
			Header $header = null) {
		if (!isset($header)) {
			$header = new Header();
		}
		$header = $header->withParameters(...$algo->headerParameters());
		// ensure that if b64 parameter is used, it's marked critical
		if ($header->hasB64Payload()) {
			if (!$header->hasCritical()) {
				$crit = new CriticalParameter(RegisteredJWTParameter::P_B64);
			} else {
				$crit = $header->critical()->withParamName(
					RegisteredJWTParameter::P_B64);
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
	public function header() {
		return new JOSE($this->_protectedHeader);
	}
	
	/**
	 * Get the signature algorithm name.
	 *
	 * @return string
	 */
	public function algorithmName() {
		return $this->header()
			->algorithm()
			->value();
	}
	
	/**
	 * Get the payload.
	 *
	 * @return string
	 */
	public function payload() {
		return $this->_payload;
	}
	
	/**
	 * Get the signature.
	 *
	 * @return string
	 */
	public function signature() {
		return $this->_signature;
	}
	
	/**
	 * Get the payload encoded for serialization.
	 *
	 * @return string
	 */
	protected function _encodedPayload() {
		$b64 = true;
		if ($this->_protectedHeader->hasB64Payload()) {
			$b64 = $this->_protectedHeader->B64Payload()->value();
		}
		return $b64 ? Base64::urlEncode($this->_payload) : $this->_payload;
	}
	
	/**
	 * Validate signature.
	 *
	 * @param SignatureAlgorithm $algo
	 * @throws \UnexpectedValueException If using different signature algorithm
	 *         then specified by the header
	 * @throws \RuntimeException If signature computation fails
	 * @return bool True if signature is valid
	 */
	public function validate(SignatureAlgorithm $algo) {
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
	 * @return bool True if signature is valid
	 */
	public function validateWithJWK(JWK $jwk) {
		$algo = SignatureAlgorithm::fromJWK($jwk, $this->header());
		return $this->validate($algo);
	}
	
	/**
	 * Validate the signature using a key from the given JWK set.
	 *
	 * Correct key shall be sought by the key ID indicated by the header.
	 *
	 * @param JWKSet $set Set of JSON Web Keys
	 * @return bool True if signature is valid
	 */
	public function validateWithJWKSet(JWKSet $set) {
		$factory = new SignatureAlgorithmFactory($this->header());
		$algo = $factory->algoByKeys($set);
		return $this->validate($algo);
	}
	
	/**
	 * Convert to compact serialization.
	 *
	 * @return string
	 */
	public function toCompact() {
		return Base64::urlEncode($this->_protectedHeader->toJSON()) . "." .
			 $this->_encodedPayload() . "." .
			 Base64::urlEncode($this->_signature);
	}
	
	/**
	 * Convert to compact serialization with payload detached.
	 *
	 * @return string
	 */
	public function toCompactDetached() {
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
	protected static function _generateSignatureInput($payload, Header $header) {
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
	public function __toString() {
		return $this->toCompact();
	}
}
