<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWS\Algorithm\HMACAlgorithm;
use Sop\JWX\JWS\Algorithm\HS512Algorithm;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Parameter\AlgorithmParameterValue;

/**
 * @group jws
 * @group hmac
 *
 * @internal
 */
class HS512Test extends TestCase
{
    public const KEY = '12345678';

    public const DATA = 'CONTENT';

    public function testCreate()
    {
        $algo = new HS512Algorithm(self::KEY);
        $this->assertInstanceOf(HMACAlgorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     */
    public function testAlgoParamValue(AlgorithmParameterValue $algo)
    {
        $this->assertEquals(JWA::ALGO_HS512, $algo->algorithmParamValue());
    }

    /**
     * @depends testCreate
     */
    public function testSign(SignatureAlgorithm $algo)
    {
        $sig = $algo->computeSignature(self::DATA);
        $this->assertEquals(64, strlen($sig));
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
