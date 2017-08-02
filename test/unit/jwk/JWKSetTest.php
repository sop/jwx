<?php

use JWX\JWK\JWK;
use JWX\JWK\JWKSet;

/**
 * @group jwk
 */
class JWKSetTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $jwkset = new JWKSet(JWK::fromArray(["kid" => "key1"]),
            JWK::fromArray(["kid" => "key2"]));
        $this->assertInstanceOf(JWKSet::class, $jwkset);
        return $jwkset;
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testHasKeyID(JWKSet $jwkset)
    {
        $this->assertTrue($jwkset->hasKeyID("key1"));
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testHasNotKeyID(JWKSet $jwkset)
    {
        $this->assertFalse($jwkset->hasKeyID("key3"));
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testKeyByID(JWKSet $jwkset)
    {
        $jwk = $jwkset->keyByID("key1");
        $this->assertInstanceOf(JWK::class, $jwk);
    }
    
    /**
     * @depends testCreate
     * @expectedException LogicException
     *
     * @param JWKSet $jwkset
     */
    public function testKeyByIDFails(JWKSet $jwkset)
    {
        $jwkset->keyByID("key3");
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testWithKeys(JWKSet $jwkset)
    {
        $set = $jwkset->withKeys(JWK::fromArray(["kid" => "key3"]));
        $this->assertInstanceOf(JWKSet::class, $set);
        return $set;
    }
    
    /**
     * @depends testWithKeys
     *
     * @param JWKSet $jwkset
     */
    public function testHasAdded(JWKSet $jwkset)
    {
        $jwk = $jwkset->keyByID("key3");
        $this->assertInstanceOf(JWK::class, $jwk);
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testFirst(JWKSet $jwkset)
    {
        $jwk = $jwkset->first();
        $this->assertInstanceOf(JWK::class, $jwk);
    }
    
    /**
     * @expectedException LogicException
     */
    public function testFirstFail()
    {
        $set = new JWKSet();
        $set->first();
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
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
     *
     * @param JWKSet $ref
     * @param JWKSet $jwkset
     */
    public function testRecoded(JWKSet $ref, JWKSet $jwkset)
    {
        // clone to reset internal state
        $this->assertEquals(clone $ref, clone $jwkset);
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testKeys(JWKSet $jwkset)
    {
        $keys = $jwkset->keys();
        $this->assertContainsOnlyInstancesOf(JWK::class, $keys);
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testCount(JWKSet $jwkset)
    {
        $this->assertCount(2, $jwkset);
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKSet $jwkset
     */
    public function testIterator(JWKSet $jwkset)
    {
        $values = array();
        foreach ($jwkset as $jwk) {
            $values[] = $jwk;
        }
        $this->assertContainsOnlyInstancesOf(JWK::class, $values);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testNoKeysParam()
    {
        JWKSet::fromArray(array());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidJSON()
    {
        JWKSet::fromJSON("null");
    }
}
