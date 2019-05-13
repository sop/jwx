<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\TypeParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class TypeParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new TypeParameter('example');
        $this->assertInstanceOf(TypeParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_TYPE, $param->name());
    }
}
