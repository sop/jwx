<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Algorithm for unsecured JWS/JWT.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.6
 * @link https://tools.ietf.org/html/rfc7519#section-6
 */
class NoneAlgorithm extends SignatureAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_NONE;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function computeSignature($data)
    {
        return "";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function validateSignature($data, $signature)
    {
        return $signature === "";
    }
    
    /**
     *
     * @see \JWX\JWS\SignatureAlgorithm::headerParameters()
     * @return \JWX\JWT\Parameter\JWTParameter[]
     */
    public function headerParameters()
    {
        return array_merge(parent::headerParameters(),
            array(AlgorithmParameter::fromAlgorithm($this)));
    }
}
