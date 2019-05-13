<?php

declare(strict_types = 1);

namespace Sop\JWX\Util;

/**
 * Class for handling big integers.
 */
class BigInt
{
    /**
     * Number.
     *
     * @var \GMP
     */
    protected $_num;

    /**
     * Constructor.
     *
     * @param \GMP $num GMP number
     */
    protected function __construct(\GMP $num)
    {
        $this->_num = $num;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->base10();
    }

    /**
     * Initialize from a base10 number.
     *
     * @param int|string $number
     *
     * @return self
     */
    public static function fromBase10($number): self
    {
        $num = gmp_init($number, 10);
        return new self($num);
    }

    /**
     * Initialize from a base256 number.
     *
     * Base64 number is an octet string of big endian, most significant word
     * first integer.
     *
     * @param string $octets
     *
     * @return self
     */
    public static function fromBase256(string $octets): self
    {
        $num = gmp_import($octets, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        return new self($num);
    }

    /**
     * Convert to base10 string.
     *
     * @return string
     */
    public function base10(): string
    {
        return gmp_strval($this->_num, 10);
    }

    /**
     * Convert to base16 string.
     *
     * @return string
     */
    public function base16(): string
    {
        return gmp_strval($this->_num, 16);
    }

    /**
     * Convert to base256 string.
     *
     * @return string
     */
    public function base256(): string
    {
        return gmp_export($this->_num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }
}
