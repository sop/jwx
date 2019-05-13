<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWT\Parameter\EncryptionAlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class EncryptionAlgorithmParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new EncryptionAlgorithmParameter(JWA::ALGO_A128CBC_HS256);
        $this->assertInstanceOf(EncryptionAlgorithmParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_ENCRYPTION_ALGORITHM,
            $param->name());
    }

    public function testFromAlgo()
    {
        $param = EncryptionAlgorithmParameter::fromAlgorithm(
            new A128CBCHS256Algorithm());
        $this->assertInstanceOf(EncryptionAlgorithmParameter::class, $param);
    }
}
