<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\Parameter\CurveParameter;

/**
 * Implements ECDSA using P-521 and SHA-512.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.4
 */
class ES512Algorithm extends ECDSAAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _curveName()
    {
        return CurveParameter::CURVE_P521;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _mdMethod()
    {
        return "sha512";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_ES512;
    }
}
