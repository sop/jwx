<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * @group jwt
 * @group validator
 *
 * @internal
 */
class EqualsValidatorTest extends TestCase
{
    private $_validator;

    public function setUp(): void
    {
        $this->_validator = new EqualsValidator();
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
            [0,    0,  true],
            [1,    1,  true],
            [-1,  -1,  true],
            [1,    0,  false],
            ['a', 'a', true],
            ['a', 'b', false],
            ['a', 'A', false],
        ];
    }
}
