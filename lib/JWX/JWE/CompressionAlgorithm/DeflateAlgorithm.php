<?php

namespace JWX\JWE\CompressionAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\CompressionAlgorithm;
use JWX\JWT\Parameter\CompressionAlgorithmParameter;


/**
 * Implements DEFLATE compression algorithm.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.3
 * @link https://tools.ietf.org/html/rfc1951
 */
class DeflateAlgorithm implements CompressionAlgorithm
{
	/**
	 * Compression level.
	 *
	 * @var int $_compressionLevel
	 */
	protected $_compressionLevel;
	
	/**
	 * Constructor
	 *
	 * @param int $level Compression level 0..9
	 */
	public function __construct($level = -1) {
		$this->_compressionLevel = (int) $level;
	}
	
	public function compress($data) {
		return gzdeflate($data, $this->_compressionLevel);
	}
	
	public function decompress($data) {
		return gzinflate($data);
	}
	
	public function compressionParamValue() {
		return JWA::ALGO_DEFLATE;
	}
	
	public function headerParameters() {
		return array(CompressionAlgorithmParameter::fromAlgorithm($this));
	}
}
