<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group key
 */
class KeyManagementAlgorithmTest extends PHPUnit_Framework_TestCase
{
    public function testFromJWK()
    {
        $jwk = SymmetricKeyJWK::fromKey("test");
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
        $algo = $algo->withKeyID("test");
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
