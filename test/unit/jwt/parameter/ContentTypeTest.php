<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\ContentTypeParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class ContentTypeParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new ContentTypeParameter('example');
        $this->assertInstanceOf(ContentTypeParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_CONTENT_TYPE, $param->name());
    }
}
