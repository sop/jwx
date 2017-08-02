<?php

use JWX\JWT\Claim\Validator\LessOrEqualValidator;

/**
 * @group jwt
 * @group validator
 */
class LessOrEqualValidatorTest extends PHPUnit_Framework_TestCase
{
    private $_validator;
    
    public function setUp()
    {
        $this->_validator = new LessOrEqualValidator();
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
            [   1,    0, false],
            [   0,    0,  true],
            [  -1,    0,  true],
            [  -1,   -1,  true],
            [  -1,   -2, false],
            [ 0.1,  0.0, false],
            [ 0.1,  0.1,  true],
            [ "1",  "0", false],
            [ "0",  "0",  true],
            ["-1",  "0",  true],
            ["-1", "-2", false]
            /* @formatter:on */
        );
    }
}
