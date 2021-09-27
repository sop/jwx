<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\PBES2CountParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class PBES2CountParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new PBES2CountParameter(1024);
        $this->assertInstanceOf(PBES2CountParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_PBES2_COUNT, $param->name());
    }
}
