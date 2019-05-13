<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jws
 *
 * @internal
 */
class SignatureAlgorithmTest extends TestCase
{
    public function testFromJWK()
    {
        $jwk = SymmetricKeyJWK::fromKey('test');
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
        $algo = SignatureAlgorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testFromJWK
     *
     * @param SignatureAlgorithm $algo
     */
    public function testWithKeyID(SignatureAlgorithm $algo)
    {
        $algo = $algo->withKeyID('id');
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testWithKeyID
     *
     * @param SignatureAlgorithm $algo
     */
    public function testHeaderParameters(SignatureAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }
}
