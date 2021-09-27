<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS;

use Sop\JWX\JWK\JWK;
use Sop\JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Header\HeaderParameters;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;
use Sop\JWX\JWT\Parameter\KeyIDParameter;

/**
 * Base class for algorithms usable for signing and validating JWS's.
 */
abstract class SignatureAlgorithm implements AlgorithmParameterValue, HeaderParameters
{
    /**
     * ID of the key used by the algorithm.
     *
     * If set, KeyID parameter shall be automatically inserted into JWS's
     * header.
     *
     * @var null|string
     */
    protected $_keyID;

    /**
     * Compute signature.
     *
     * @param string $data Data for which the signature is computed
     */
    abstract public function computeSignature(string $data): string;

    /**
     * Validate signature.
     *
     * @param string $data      Data to validate
     * @param string $signature Signature to compare
     */
    abstract public function validateSignature(string $data, string $signature): bool;

    /**
     * Initialize signature algorithm from a JWK and a header.
     *
     * @param JWK    $jwk    JSON Web Key
     * @param Header $header Header
     */
    public static function fromJWK(JWK $jwk, Header $header): SignatureAlgorithm
    {
        $factory = new SignatureAlgorithmFactory($header);
        return $factory->algoByKey($jwk);
    }

    /**
     * Get self with key ID.
     *
     * @param null|string $id Key ID or null to remove
     */
    public function withKeyID(?string $id): self
    {
        $obj = clone $this;
        $obj->_keyID = $id;
        return $obj;
    }

    /**
     * {@inheritdoc}
     */
    public function headerParameters(): array
    {
        $params = [];
        if (isset($this->_keyID)) {
            $params[] = new KeyIDParameter($this->_keyID);
        }
        return $params;
    }
}
