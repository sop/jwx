<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\JWKSet;

/**
 * @group jwk
 *
 * @internal
 */
class JWKSetTest extends TestCase
{
    public function testCreate()
    {
        $jwkset = new JWKSet(JWK::fromArray(['kid' => 'key1']),
            JWK::fromArray(['kid' => 'key2']));
        $this->assertInstanceOf(JWKSet::class, $jwkset);
        return $jwkset;
    }

    /**
     * @depends testCreate
     */
    public function testHasKeyID(JWKSet $jwkset)
    {
        $this->assertTrue($jwkset->hasKeyID('key1'));
    }

    /**
     * @depends testCreate
     */
    public function testHasNotKeyID(JWKSet $jwkset)
    {
        $this->assertFalse($jwkset->hasKeyID('key3'));
    }

    /**
     * @depends testCreate
     */
    public function testKeyByID(JWKSet $jwkset)
    {
        $jwk = $jwkset->keyByID('key1');
        $this->assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @depends testCreate
     */
    public function testKeyByIDFails(JWKSet $jwkset)
    {
        $this->expectException(\LogicException::class);
        $jwkset->keyByID('key3');
    }

    /**
     * @depends testCreate
     */
    public function testWithKeys(JWKSet $jwkset)
    {
        $set = $jwkset->withKeys(JWK::fromArray(['kid' => 'key3']));
        $this->assertInstanceOf(JWKSet::class, $set);
        return $set;
    }

    /**
     * @depends testWithKeys
     */
    public function testHasAdded(JWKSet $jwkset)
    {
        $jwk = $jwkset->keyByID('key3');
        $this->assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @depends testCreate
     */
    public function testFirst(JWKSet $jwkset)
    {
        $jwk = $jwkset->first();
        $this->assertInstanceOf(JWK::class, $jwk);
    }

    public function testFirstFail()
    {
        $set = new JWKSet();
        $this->expectException(\LogicException::class);
        $set->first();
    }

    /**
     * @depends testCreate
     */
    public function testToJSON(JWKSet $jwkset)
    {
        $json = $jwkset->toJSON();
        $this->assertJson($json);
        return $json;
    }

    /**
     * @depends testToJSON
     *
     * @param string $json
     */
    public function testFromJSON($json)
    {
        $jwkset = JWKSet::fromJSON($json);
        $this->assertInstanceOf(JWKSet::class, $jwkset);
        return $jwkset;
    }

    /**
     * @depends testCreate
     * @depends testFromJSON
     */
    public function testRecoded(JWKSet $ref, JWKSet $jwkset)
    {
        // clone to reset internal state
        $this->assertEquals(clone $ref, clone $jwkset);
    }

    /**
     * @depends testCreate
     */
    public function testKeys(JWKSet $jwkset)
    {
        $keys = $jwkset->keys();
        $this->assertContainsOnlyInstancesOf(JWK::class, $keys);
    }

    /**
     * @depends testCreate
     */
    public function testCount(JWKSet $jwkset)
    {
        $this->assertCount(2, $jwkset);
    }

    /**
     * @depends testCreate
     */
    public function testIterator(JWKSet $jwkset)
    {
        $values = [];
        foreach ($jwkset as $jwk) {
            $values[] = $jwk;
        }
        $this->assertContainsOnlyInstancesOf(JWK::class, $values);
    }

    public function testNoKeysParam()
    {
        $this->expectException(\UnexpectedValueException::class);
        JWKSet::fromArray([]);
    }

    public function testInvalidJSON()
    {
        $this->expectException(\UnexpectedValueException::class);
        JWKSet::fromJSON('null');
    }
}
