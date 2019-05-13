<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\Parameter\CurveParameter;

/**
 * Implements ECDSA using P-521 and SHA-512.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.4
 */
class ES512Algorithm extends ECDSAAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_ES512;
    }

    /**
     * {@inheritdoc}
     */
    protected function _curveName(): string
    {
        return CurveParameter::CURVE_P521;
    }

    /**
     * {@inheritdoc}
     */
    protected function _mdMethod(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
