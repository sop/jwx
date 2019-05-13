<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm\Feature;

/**
 * Trait for key algorithms employing random CEK generation.
 */
trait RandomCEK
{
    /**
     * Generate a random content encryption key.
     *
     * @param int $length Key length in bytes
     *
     * @throws \RuntimeException
     *
     * @return string
     */
    public function cekForEncryption(int $length): string
    {
        $ret = openssl_random_pseudo_bytes($length);
        if (false === $ret) {
            throw new \RuntimeException('openssl_random_pseudo_bytes() failed.');
        }
        return $ret;
    }
}
