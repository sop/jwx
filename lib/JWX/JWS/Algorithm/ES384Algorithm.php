<?php

declare(strict_types = 1);

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\Parameter\CurveParameter;

/**
 * Implements ECDSA using P-384 and SHA-384.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.4
 */
class ES384Algorithm extends ECDSAAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _curveName(): string
    {
        return CurveParameter::CURVE_P384;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _mdMethod(): string
    {
        return "sha384";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_ES384;
    }
}
