<?php

use JWX\Util\UUIDv4;

/**
 * @group util
 * @group uuid
 */
class UUIDv4Test extends PHPUnit_Framework_TestCase
{
    const UUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    
    public function testCreate()
    {
        $uuid = new UUIDv4(self::UUID);
        $this->assertInstanceOf(UUIDv4::class, $uuid);
        return $uuid;
    }
    
    /**
     * @depends testCreate
     *
     * @param UUIDv4 $uuid
     */
    public function testCanonical(UUIDv4 $uuid)
    {
        $this->assertEquals(self::UUID, $uuid->canonical());
    }
    
    /**
     * @depends testCreate
     *
     * @param UUIDv4 $uuid
     */
    public function testToString(UUIDv4 $uuid)
    {
        $str = strval($uuid);
        $this->assertEquals(self::UUID, $str);
    }
    
    public function testCreateRandom()
    {
        $uuid = UUIDv4::createRandom();
        $this->assertInstanceOf(UUIDv4::class, $uuid);
    }
}
