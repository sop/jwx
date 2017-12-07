<?php

declare(strict_types = 1);

namespace JWX\Util;

/* @formatter:off */
/*
   Layout and Byte Order
   http://tools.ietf.org/search/rfc4122#section-4.1.2
   
   0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          time_low                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       time_mid                |         time_hi_and_version   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |clk_seq_hi_res |  clk_seq_low  |         node (0-1)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         node (2-5)                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
/* @formatter:on */

/**
 * UUID version 4
 *
 * @link http://tools.ietf.org/search/rfc4122#section-4.4
 */
class UUIDv4
{
    /**
     * UUID.
     *
     * @var string $_uuid
     */
    protected $_uuid;
    
    /**
     * Constructor.
     *
     * @param string $uuid UUIDv4 in canonical hexadecimal format
     */
    public function __construct(string $uuid)
    {
        // @todo Check that UUID is version 4
        $this->_uuid = $uuid;
    }
    
    /**
     * Create new random UUIDv4.
     *
     * @return self
     */
    public static function createRandom(): self
    {
        /*
         1. Set the two most significant bits (bits 6 and 7) of
         the clock_seq_hi_and_reserved to zero and one, respectively.
         
         2. Set the four most significant bits (bits 12 through 15) of
         the time_hi_and_version field to the 4-bit version number
         from Section 4.1.3.
         
         3. Set all the other bits to randomly (or pseudo-randomly)
         chosen values.
         */
        $uuid = sprintf("%04x%04x-%04x-%04x-%02x%02x-%04x%04x%04x",
            // time_low
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), 
            // time_mid
            mt_rand(0, 0xffff), 
            // time_hi_and_version
            mt_rand(0, 0x0fff) | 0x4000, 
            // clk_seq_hi_res
            mt_rand(0, 0x3f) | 0x80, 
            // clk_seq_low
            mt_rand(0, 0xff), 
            // node
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff));
        return new self($uuid);
    }
    
    /**
     * Get UUIDv4 in canonical form.
     *
     * @return string
     */
    public function canonical(): string
    {
        return $this->_uuid;
    }
    
    /**
     *
     * @return string
     */
    public function __toString()
    {
        return $this->canonical();
    }
}
