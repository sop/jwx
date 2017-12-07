<?php

use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\TypeParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group header
 */
class HeaderTest extends TestCase
{
    /**
     *
     * @return Header
     */
    public function testCreate()
    {
        $header = Header::fromArray(array("alg" => "none", "typ" => "test"));
        $this->assertInstanceOf(Header::class, $header);
        return $header;
    }
    
    public function testCreateEmpty()
    {
        $header = new Header();
        $this->assertInstanceOf(Header::class, $header);
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testHas(Header $header)
    {
        $this->assertTrue($header->has("typ"));
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testHasMany(Header $header)
    {
        $this->assertTrue($header->has("typ", "alg"));
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testHasNot(Header $header)
    {
        $this->assertFalse($header->has("typ", "nope"));
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testGet(Header $header)
    {
        $param = $header->get(JWTParameter::PARAM_TYPE);
        $this->assertInstanceOf(TypeParameter::class, $param);
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param Header $header
     */
    public function testGetFails(Header $header)
    {
        $header->get("nope");
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testParameters(Header $header)
    {
        $this->assertContainsOnlyInstancesOf(JWTParameter::class,
            $header->parameters());
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testCount(Header $header)
    {
        $this->assertCount(2, $header);
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testIterator(Header $header)
    {
        $values = array();
        foreach ($header as $param) {
            $values[] = $param;
        }
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $values);
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testAdd(Header $header)
    {
        $header = $header->withParameters(new ContentTypeParameter("test"));
        $this->assertCount(3, $header);
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     */
    public function testModify(Header $header)
    {
        $header = $header->withParameters(new TypeParameter("modified"));
        $this->assertEquals("modified",
            $header->get(JWTParameter::PARAM_TYPE)
                ->value());
    }
    
    /**
     * @depends testCreate
     *
     * @param Header $header
     * @return string
     */
    public function testToJSON(Header $header)
    {
        $json = $header->toJSON();
        $this->assertJson($json);
        return $json;
    }
    
    public function testToJSONEmpty()
    {
        $header = new Header();
        $this->assertEquals("", $header->toJSON());
    }
    
    /**
     * @depends testToJSON
     *
     * @param string $json
     * @return Header
     */
    public function testFromJSON($json)
    {
        $header = Header::fromJSON($json);
        $this->assertInstanceOf(Header::class, $header);
        return $header;
    }
    
    /**
     * @depends testCreate
     * @depends testFromJSON
     *
     * @param Header $ref
     * @param Header $recoded
     */
    public function testRecode(Header $ref, Header $recoded)
    {
        $this->assertEquals($ref, $recoded);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJSONFail()
    {
        Header::fromJSON("null");
    }
}
