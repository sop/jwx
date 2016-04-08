<?php

namespace JWX\JWS;

use JWX\JOSE\JOSE;
use JWX\JOSE\Parameter\AlgorithmParameter;
use JWX\JOSE\Parameter\RegisteredParameter;
use JWX\Util\Base64;


class JWS
{
	/**
	 * Header
	 *
	 * @var JOSE $_protectedHeader
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
	 * @param JOSE $header
	 * @param string $payload
	 * @param string $signature
	 */
	public function __construct(JOSE $protected_header, $payload, $signature) {
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
				"Not valid JWS compact serialization");
		}
		$header = JOSE::fromJSON(Base64::urlDecode($segments[0]));
		$payload = Base64::urlDecode($segments[1]);
		$signature = Base64::urlDecode($segments[2]);
		return new self($header, $payload, $signature);
	}
	
	/**
	 * Initialize by signing payload with given algorithm
	 *
	 * @param string $payload
	 * @param SignatureAlgorithm $algo
	 * @return self
	 */
	public static function sign($payload, SignatureAlgorithm $algo) {
		$header = new JOSE(new AlgorithmParameter($algo->algorithmParamValue()));
		$data = Base64::urlEncode($header->toJSON()) . "." .
			 Base64::urlEncode($payload);
		$signature = $algo->computeSignature($data);
		return new self($header, $payload, $signature);
	}
	
	public function header() {
		return $this->_protectedHeader;
	}
	
	public function algorithmName() {
		$jose = $this->header();
		return $jose->get(RegisteredParameter::NAME_ALGORITHM)->value();
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
}
