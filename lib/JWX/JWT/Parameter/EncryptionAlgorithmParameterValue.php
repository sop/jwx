<?php

namespace JWX\JWT\Parameter;

/**
 * Interface for algorithms providing value for 'enc' header parameter.
 */
interface EncryptionAlgorithmParameterValue
{
    /**
     * Get algorithm type as an 'enc' parameter value.
     *
     * @return string
     */
    public function encryptionAlgorithmParamValue();
}
