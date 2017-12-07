<?php

use JWX\Util\BigInt;
use PHPUnit\Framework\TestCase;

/**
 * @group util
 * @group bigint
 */
class BigIntTest extends TestCase
{
    const BASE_10 = "255";
    
    public function testCreate()
    {
        $bi = BigInt::fromBase10(self::BASE_10);
        $this->assertInstanceOf(BigInt::class, $bi);
        return $bi;
    }
    
    /**
     * @depends testCreate
     *
     * @param BigInt $bi
     */
    public function testBase10(BigInt $bi)
    {
        $this->assertEquals(self::BASE_10, $bi->base10());
    }
    
    /**
     * @depends testCreate
     *
     * @param BigInt $bi
     */
    public function testBase16(BigInt $bi)
    {
        $this->assertEquals("ff", $bi->base16());
    }
    
    /**
     * @depends testCreate
     *
     * @param BigInt $bi
     */
    public function testBase256(BigInt $bi)
    {
        $this->assertEquals("\xff", $bi->base256());
    }
    
    /**
     * @depends testCreate
     *
     * @param BigInt $bi
     */
    public function testToString(BigInt $bi)
    {
        $str = strval($bi);
        $this->assertEquals(self::BASE_10, $str);
    }
    
    public function testFromBase256()
    {
        $bi = BigInt::fromBase256("\xff");
        $this->assertEquals("255", $bi);
    }
}
