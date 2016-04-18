<?php

namespace JWX\JWS;

use JWX\Util\Base64;
use JWX\JWT\JOSE;
use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\CriticalParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


class JWS
{
	/**
	 * Header
	 *
	 * @var Header $_protectedHeader
	 */
	protected $_protectedHeader;
	
	/**
	 * Payload
	 *
	 * @var string $_payload
	 */
	protected $_payload;
	
	/**
	 * Signature
	 *
	 * @var string $_signature
	 */
	protected $_signature;
	
	/**
	 * Constructor
	 *
	 * @param Header $header JWS Protected Header
	 * @param string $payload JWS Payload
	 * @param string $signature JWS Signature
	 */
	protected function __construct(Header $protected_header, $payload, 
		$signature) {
		$this->_protectedHeader = $protected_header;
		$this->_payload = $payload;
		$this->_signature = $signature;
	}
	
	/**
	 * Initialize from compact serialization
	 *
	 * @param string $data
	 * @return self
	 */
	public static function fromCompact($data) {
		return self::fromParts(explode(".", $data));
	}
	
	/**
	 * Initialize from parts of compact serialization
	 *
	 * @param array $parts
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromParts(array $parts) {
		if (count($parts) != 3) {
			throw new \UnexpectedValueException(
				"Invalid JWS compact serialization");
		}
		$header = Header::fromJSON(Base64::urlDecode($parts[0]));
		$b64 = $header->has(RegisteredJWTParameter::P_B64) ?
			$header->get(RegisteredJWTParameter::P_B64)->value() : true;
		$payload = $b64 ? Base64::urlDecode($parts[1]) : $parts[1];
		$signature = Base64::urlDecode($parts[2]);
		return new self($header, $payload, $signature);
	}
	
	/**
	 * Initialize by signing payload with given algorithm
	 *
	 * @param string $payload JWS Payload
	 * @param SignatureAlgorithm $algo Signature algorithm
	 * @param Header|null $header Desired header. Algorithm specific
	 *        parameters are added automatically.
	 * @return self
	 */
	public static function sign($payload, SignatureAlgorithm $algo, 
		Header $header = null) {
		if (!isset($header)) {
			$header = new Header();
		}
		$header = $header->withParameters(
			AlgorithmParameter::fromAlgorithm($algo));
		// ensure that if b64 parameter is used, it's marked critical
		if ($header->has(RegisteredJWTParameter::P_B64)) {
			if (!$header->has(RegisteredJWTParameter::P_CRIT)) {
				$crit = new CriticalParameter(RegisteredJWTParameter::P_B64);
			} else {
				$crit = $header->get(RegisteredJWTParameter::P_CRIT)
					->with(RegisteredJWTParameter::P_B64);
			}
			$header = $header->withParameters($crit);
		}
		$signature_input = self::_getSignatureInput($payload, $header);
		$signature = $algo->computeSignature($signature_input);
		return new self($header, $payload, $signature);
	}
	
	/**
	 * Get JOSE header
	 *
	 * @return JOSE
	 */
	public function header() {
		return new JOSE($this->_protectedHeader);
	}
	
	/**
	 * Get signature algorithm name
	 *
	 * @return string
	 */
	public function algorithmName() {
		return $this->header()
			->get(RegisteredJWTParameter::PARAM_ALGORITHM)
			->value();
	}
	
	/**
	 * Get payload
	 *
	 * @return string
	 */
	public function payload() {
		return $this->_payload;
	}
	
	/**
	 * Get payload encoded for serialization
	 *
	 * @return string
	 */
	protected function _encodedPayload() {
		$b64 = $this->_protectedHeader->has(RegisteredJWTParameter::P_B64) ?
			$this->_protectedHeader->get(
				RegisteredJWTParameter::P_B64)->value() : true;
		return $b64 ? Base64::urlEncode($this->_payload) : $this->_payload;
	}
	
	/**
	 * Validate signature
	 *
	 * @param SignatureAlgorithm $algo
	 * @throws \UnexpectedValueException
	 * @return bool True if signature is valid
	 */
	public function validate(SignatureAlgorithm $algo) {
		if ($algo->algorithmParamValue() != $this->algorithmName()) {
			throw new \UnexpectedValueException("Invalid signature algorithm");
		}
		$data = self::_getSignatureInput($this->_payload, 
			$this->_protectedHeader);
		return $algo->validateSignature($data, $this->_signature);
	}
	
	/**
	 * Convert to compact serialization
	 *
	 * @return string
	 */
	public function toCompact() {
		return Base64::urlEncode($this->_protectedHeader->toJSON()) . "." .
			 $this->_encodedPayload() . "." .
			 Base64::urlEncode($this->_signature);
	}
	
	/**
	 * Convert to compact serialization with payload detached
	 *
	 * @return string
	 */
	public function toCompactDetached() {
		return Base64::urlEncode($this->_protectedHeader->toJSON()) . ".." .
			 Base64::urlEncode($this->_signature);
	}
	
	/**
	 * Get input for signature algorithm
	 *
	 * @param string $payload Payload
	 * @param Header $header Protected header
	 * @return string
	 */
	protected static function _getSignatureInput($payload, Header $header) {
		$b64 = $header->has(RegisteredJWTParameter::P_B64) ?
			$header->get(RegisteredJWTParameter::P_B64)->value() : true;
		$data = Base64::urlEncode($header->toJSON()) . ".";
		$data .= $b64 ? Base64::urlEncode($payload) : $payload;
		return $data;
	}
	
	/**
	 * Convert JWS to string
	 *
	 * @return string
	 */
	public function __toString() {
		return $this->toCompact();
	}
}
