<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class KeyManagementAlgorithmTest extends TestCase
{
    public function testFromJWK()
    {
        $jwk = SymmetricKeyJWK::fromKey('test');
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
        $algo = KeyManagementAlgorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(KeyManagementAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testFromJWK
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testWithKeyID(KeyManagementAlgorithm $algo)
    {
        $algo = $algo->withKeyID('test');
        $this->assertInstanceOf(KeyManagementAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testWithKeyID
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testHeaderParameters(KeyManagementAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }
}
