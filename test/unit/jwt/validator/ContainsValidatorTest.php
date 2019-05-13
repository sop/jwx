<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Validator\ContainsValidator;

/**
 * @group jwt
 * @group validator
 *
 * @internal
 */
class ContainsValidatorTest extends TestCase
{
    private $_validator;

    public function setUp(): void
    {
        $this->_validator = new ContainsValidator();
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
            [['a'], 'a', true],
            [['a',  'b', 'c'], 'b', true],
            [['a',  'b', 'c'], 'd', false],
            [['a',  'b', 'c'], 'B', false],
            ['a',   'a', true],
            ['a',   'A', false],
            [[],    '',  false],
        ];
    }
}
