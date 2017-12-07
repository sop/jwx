<?php

declare(strict_types = 1);

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
     * Constructor.
     *
     * @param int $level Compression level 0..9
     */
    public function __construct(int $level = -1)
    {
        if ($level < -1 || $level > 9) {
            throw new \DomainException("Compression level must be -1..9.");
        }
        $this->_compressionLevel = (int) $level;
    }
    
    /**
     *
     * @see \JWX\JWE\CompressionAlgorithm::compress()
     * @throws \RuntimeException
     */
    public function compress(string $data): string
    {
        $ret = @gzdeflate($data, $this->_compressionLevel);
        if (false === $ret) {
            $err = error_get_last();
            $msg = isset($err) && __FILE__ == $err['file'] ? $err['message'] : null;
            throw new \RuntimeException($msg ?? "gzdeflate() failed.");
        }
        return $ret;
    }
    
    /**
     *
     * @see \JWX\JWE\CompressionAlgorithm::decompress()
     * @throws \RuntimeException
     */
    public function decompress(string $data): string
    {
        $ret = @gzinflate($data);
        if (false === $ret) {
            $err = error_get_last();
            $msg = isset($err) && __FILE__ == $err['file'] ? $err['message'] : null;
            throw new \RuntimeException($msg ?? "gzinflate() failed.");
        }
        return $ret;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function compressionParamValue(): string
    {
        return JWA::ALGO_DEFLATE;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return array(CompressionAlgorithmParameter::fromAlgorithm($this));
    }
}
