<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWS\Algorithm\HMACAlgorithm;
use Sop\JWX\JWS\Algorithm\HS256Algorithm;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;

/**
 * @group jws
 * @group hmac
 *
 * @internal
 */
class HS256Test extends TestCase
{
    const KEY = '12345678';

    const DATA = 'CONTENT';

    public function testCreate()
    {
        $algo = new HS256Algorithm(self::KEY);
        $this->assertInstanceOf(HMACAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param AlgorithmParameterValue $algo
     */
    public function testAlgoParamValue(AlgorithmParameterValue $algo)
    {
        $this->assertEquals(JWA::ALGO_HS256, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     *
     * @param SignatureAlgorithm $algo
     */
    public function testSign(SignatureAlgorithm $algo)
    {
        $sig = $algo->computeSignature(self::DATA);
        $this->assertEquals(32, strlen($sig));
        return $sig;
    }

    /**
     * @depends testCreate
     * @depends testSign
     *
     * @param SignatureAlgorithm $algo
     * @param string             $signature
     */
    public function testValidate(SignatureAlgorithm $algo, $signature)
    {
        $this->assertTrue($algo->validateSignature(self::DATA, $signature));
    }
}
