<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Algorithm for unsecured JWS/JWT.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.6
 * @see https://tools.ietf.org/html/rfc7519#section-6
 */
class NoneAlgorithm extends SignatureAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_NONE;
    }

    /**
     * {@inheritdoc}
     */
    public function computeSignature(string $data): string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function validateSignature(string $data, string $signature): bool
    {
        return '' === $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        return array_merge(parent::headerParameters(),
            [AlgorithmParameter::fromAlgorithm($this)]);
    }
}
