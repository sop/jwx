<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWT\Header\Header;

/**
 * Factory class to construct key management algorithm instances.
 */
class KeyAlgorithmFactory
{
    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    public const MAP_ALGO_TO_CLASS = [
        JWA::ALGO_A128KW => A128KWAlgorithm::class,
        JWA::ALGO_A192KW => A192KWAlgorithm::class,
        JWA::ALGO_A128KW => A256KWAlgorithm::class,
        JWA::ALGO_A128GCMKW => A128GCMKWAlgorithm::class,
        JWA::ALGO_A192GCMKW => A192GCMKWAlgorithm::class,
        JWA::ALGO_A256GCMKW => A256GCMKWAlgorithm::class,
        JWA::ALGO_PBES2_HS256_A128KW => PBES2HS256A128KWAlgorithm::class,
        JWA::ALGO_PBES2_HS384_A192KW => PBES2HS384A192KWAlgorithm::class,
        JWA::ALGO_PBES2_HS512_A256KW => PBES2HS512A256KWAlgorithm::class,
        JWA::ALGO_DIR => DirectCEKAlgorithm::class,
        JWA::ALGO_RSA1_5 => RSAESPKCS1Algorithm::class,
        JWA::ALGO_RSA_OAEP => RSAESOAEPAlgorithm::class,
    ];
    /**
     * Header.
     *
     * @var Header
     */
    protected $_header;

    /**
     * Constructor.
     */
    public function __construct(Header $header)
    {
        $this->_header = $header;
    }

    /**
     * Get key management algorithm by given JWK.
     */
    public function algoByKey(JWK $jwk): KeyManagementAlgorithm
    {
        $alg = JWA::deriveAlgorithmName($this->_header, $jwk);
        $cls = self::_algoClassByName($alg);
        return $cls::fromJWK($jwk, $this->_header);
    }

    /**
     * Get key management algorithm using a matching key from given JWK set.
     *
     * @throws \UnexpectedValueException If a key cannot be found
     */
    public function algoByKeys(JWKSet $set): KeyManagementAlgorithm
    {
        if (!$this->_header->hasKeyID()) {
            throw new \UnexpectedValueException('No key ID paremeter.');
        }
        $id = $this->_header->keyID()->value();
        if (!$set->hasKeyID($id)) {
            throw new \UnexpectedValueException("No key for ID '{$id}'.");
        }
        return $this->algoByKey($set->keyByID($id));
    }

    /**
     * Get the algorithm implementation class name by an algorithm name.
     *
     * @param string $alg Algorithm name
     *
     * @throws \UnexpectedValueException
     *
     * @return string Class name
     */
    private static function _algoClassByName(string $alg): string
    {
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException(
                "Algorithm '{$alg}' not supported.");
        }
        return self::MAP_ALGO_TO_CLASS[$alg];
    }
}
