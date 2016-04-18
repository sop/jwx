<?php

namespace JWX\JWE\CompressionAlgorithm;

use JWX\JWE\CompressionAlgorithm;


class DeflateAlgorithm implements CompressionAlgorithm
{
	/**
	 * Compression level
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
}
