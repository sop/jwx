<?php

namespace JWX\JWE;


interface CompressionAlgorithm
{
	/**
	 * Compress data
	 *
	 * @param string $data Compressed data
	 */
	public function compress($data);
	
	/**
	 * Decompress data
	 *
	 * @param string $data Uncompressed data
	 */
	public function decompress($data);
}
