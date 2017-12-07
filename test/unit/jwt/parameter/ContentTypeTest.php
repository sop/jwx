<?php

use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\JWT\Parameter\JWTParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group parameter
 */
class ContentTypeParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new ContentTypeParameter("example");
        $this->assertInstanceOf(ContentTypeParameter::class, $param);
        return $param;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_CONTENT_TYPE, $param->name());
    }
}
