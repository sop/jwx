<?php

use JWX\JWT\Claim\Validator\GreaterValidator;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group validator
 */
class GreaterValidatorTest extends TestCase
{
    private $_validator;
    
    public function setUp()
    {
        $this->_validator = new GreaterValidator();
    }
    
    public function tearDown()
    {
        $this->_validator = null;
    }
    
    /**
     * @dataProvider provider
     */
    public function testValidator($a, $b, $result)
    {
        $this->assertEquals($this->_validator->validate($a, $b), $result);
    }
    
    public function provider()
    {
        return array(
            /* @formatter:off */
            [   1,    0,  true],
            [   0,    0, false],
            [  -1,    0, false],
            [  -1,   -2,  true],
            [ 0.1,  0.0,  true],
            [ "1",  "0",  true],
            [ "0",  "0", false],
            ["-1",  "0", false],
            ["-1", "-2",  true]
            /* @formatter:on */
        );
    }
}
