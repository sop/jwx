<?php

declare(strict_types = 1);

namespace JWX\JWS;

use JWX\JWK\JWK;
use JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\HeaderParameters;
use JWX\JWT\Parameter\AlgorithmParameterValue;
use JWX\JWT\Parameter\KeyIDParameter;

/**
 * Base class for algorithms usable for signing and validating JWS's.
 */
abstract class SignatureAlgorithm implements 
    AlgorithmParameterValue,
    HeaderParameters
{
    /**
     * ID of the key used by the algorithm.
     *
     * If set, KeyID parameter shall be automatically inserted into JWS's
     * header.
     *
     * @var string|null $_keyID
     */
    protected $_keyID;
    
    /**
     * Compute signature.
     *
     * @param string $data Data for which the signature is computed
     * @return string
     */
    abstract public function computeSignature(string $data): string;
    
    /**
     * Validate signature.
     *
     * @param string $data Data to validate
     * @param string $signature Signature to compare
     * @return bool
     */
    abstract public function validateSignature(string $data, string $signature): bool;
    
    /**
     * Initialize signature algorithm from a JWK and a header.
     *
     * @param JWK $jwk JSON Web Key
     * @param Header $header Header
     * @return SignatureAlgorithm
     */
    public static function fromJWK(JWK $jwk, Header $header)
    {
        $factory = new SignatureAlgorithmFactory($header);
        return $factory->algoByKey($jwk);
    }
    
    /**
     * Get self with key ID.
     *
     * @param string|null $id Key ID or null to remove
     * @return self
     */
    public function withKeyID($id): self
    {
        $obj = clone $this;
        $obj->_keyID = $id;
        return $obj;
    }
    
    /**
     *
     * @see \JWX\JWT\Header\HeaderParameters::headerParameters()
     * @return \JWX\JWT\Parameter\JWTParameter[]
     */
    public function headerParameters(): array
    {
        $params = array();
        if (isset($this->_keyID)) {
            $params[] = new KeyIDParameter($this->_keyID);
        }
        return $params;
    }
}
