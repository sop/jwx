<?php

use JWX\JWT\Claim\Validator\ContainsValidator;

/**
 * @group jwt
 * @group validator
 */
class ContainsValidatorTest extends PHPUnit_Framework_TestCase
{
    private $_validator;
    
    public function setUp()
    {
        $this->_validator = new ContainsValidator();
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
            [["a"], "a", true],
            [["a", "b", "c"], "b", true],
            [["a", "b", "c"], "d", false],
            [["a", "b", "c"], "B", false],
            ["a", "a", true],
            ["a", "A", false],
            [[], "", false]
            /* @formatter:on */
        );
    }
}
