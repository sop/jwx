<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Validator\LessValidator;

/**
 * @group jwt
 * @group validator
 *
 * @internal
 */
class LessValidatorTest extends TestCase
{
    private $_validator;

    public function setUp(): void
    {
        $this->_validator = new LessValidator();
    }

    public function tearDown(): void
    {
        $this->_validator = null;
    }

    /**
     * @dataProvider provider
     *
     * @param mixed $a
     * @param mixed $b
     * @param mixed $result
     */
    public function testValidator($a, $b, $result)
    {
        $this->assertEquals($this->_validator->validate($a, $b), $result);
    }

    public function provider()
    {
        return [
            [1,     0,   false],
            [0,     0,   false],
            [-1,    0,   true],
            [-1,   -2,   false],
            [0.1,   0.0, false],
            ['1',  '0',  false],
            ['0',  '0',  false],
            ['-1', '0',  true],
            ['-1', '-2', false],
        ];
    }
}
