<?php

namespace JWX\JWS;

use JWX\Util\Base64;
use JWX\JWT\JOSE;
use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
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
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromCompact($data) {
		$segments = explode(".", $data);
		if (count($segments) != 3) {
			throw new \UnexpectedValueException(
				"Invalid JWS compact serialization");
		}
		$header = Header::fromJSON(Base64::urlDecode($segments[0]));
		$payload = Base64::urlDecode($segments[1]);
		$signature = Base64::urlDecode($segments[2]);
		return new self($header, $payload, $signature);
	}
	
	/**
	 * Initialize by signing payload with given algorithm
	 *
	 * @param string $payload JWS Payload
	 * @param Header $header Desired header. Algorithm specific parameters are
	 *        added automatically.
	 * @param SignatureAlgorithm $algo Signature algorithm
	 * @return self
	 */
	public static function sign($payload, Header $header, 
			SignatureAlgorithm $algo) {
		$header = $header->withParameters(
			AlgorithmParameter::fromAlgorithm($algo));
		$data = Base64::urlEncode($header->toJSON()) . "." .
			 Base64::urlEncode($payload);
		$signature = $algo->computeSignature($data);
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
		$data = Base64::urlEncode($this->_protectedHeader->toJSON()) . "." .
			 Base64::urlEncode($this->_payload);
		return $algo->validateSignature($data, $this->_signature);
	}
	
	/**
	 * Convert to compact serialization
	 *
	 * @return string
	 */
	public function toCompact() {
		return Base64::urlEncode($this->_protectedHeader->toJSON()) . "." .
			 Base64::urlEncode($this->_payload) . "." .
			 Base64::urlEncode($this->_signature);
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
