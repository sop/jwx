<?php

namespace JWX\JWE;


/**
 * Interface for algorithms that may be used to compress and decompress data.
 */
interface CompressionAlgorithm
{
	/**
	 * Compress data.
	 *
	 * @param string $data Compressed data
	 */
	public function compress($data);
	
	/**
	 * Decompress data.
	 *
	 * @param string $data Uncompressed data
	 */
	public function decompress($data);
}
