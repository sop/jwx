<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\Parameter\AlgorithmParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class JWKAlgorithmParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new AlgorithmParameter(JWA::ALGO_A128CBC_HS256);
        $this->assertInstanceOf(AlgorithmParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_ALGORITHM, $param->name());
    }

    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testFromNameAndValue(JWKParameter $param)
    {
        $p = JWKParameter::fromNameAndValue($param->name(), $param->value());
        $this->assertEquals($p, $param);
    }
}
