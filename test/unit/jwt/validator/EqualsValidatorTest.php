<?php

use JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * @group jwt
 * @group validator
 */
class EqualsValidatorTest extends PHPUnit_Framework_TestCase
{
    private $_validator;
    
    public function setUp()
    {
        $this->_validator = new EqualsValidator();
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
            [  0,   0,  true],
            [  1,   1,  true],
            [ -1,  -1,  true],
            [  1,   0, false],
            ["a", "a",  true],
            ["a", "b", false],
            ["a", "A", false]
            /* @formatter:on */
        );
    }
}
