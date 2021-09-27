<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\Util\UUIDv4;

/**
 * @group util
 * @group uuid
 *
 * @internal
 */
class UUIDv4Test extends TestCase
{
    public const UUID = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

    public function testCreate()
    {
        $uuid = new UUIDv4(self::UUID);
        $this->assertInstanceOf(UUIDv4::class, $uuid);
        return $uuid;
    }

    /**
     * @depends testCreate
     */
    public function testCanonical(UUIDv4 $uuid)
    {
        $this->assertEquals(self::UUID, $uuid->canonical());
    }

    /**
     * @depends testCreate
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
