<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Validator\LessOrEqualValidator;

/**
 * @group jwt
 * @group validator
 *
 * @internal
 */
class LessOrEqualValidatorTest extends TestCase
{
    private $_validator;

    public function setUp(): void
    {
        $this->_validator = new LessOrEqualValidator();
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
            [0,     0,   true],
            [-1,    0,   true],
            [-1,   -1,   true],
            [-1,   -2,   false],
            [0.1,   0.0, false],
            [0.1,   0.1, true],
            ['1',  '0',  false],
            ['0',  '0',  true],
            ['-1', '0',  true],
            ['-1', '-2', false],
        ];
    }
}
