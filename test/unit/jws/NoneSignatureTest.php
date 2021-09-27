<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWS\Algorithm\NoneAlgorithm;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;

/**
 * @group jws
 *
 * @internal
 */
class NoneSignatureTest extends TestCase
{
    public const DATA = 'CONTENT';

    public function testCreate()
    {
        $algo = new NoneAlgorithm();
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(AlgorithmParameterValue $algo)
    {
        $this->assertEquals(JWA::ALGO_NONE, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testSign(SignatureAlgorithm $algo)
    {
        $sig = $algo->computeSignature(self::DATA);
        $this->assertEquals('', $sig);
        return $sig;
    }

    /**
     * @depends testCreate
     * @depends testSign
     *
     * @param string $signature
     */
    public function testValidate(SignatureAlgorithm $algo, $signature)
    {
        $this->assertTrue($algo->validateSignature(self::DATA, $signature));
    }
}
