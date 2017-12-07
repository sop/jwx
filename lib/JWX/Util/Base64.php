<?php

declare(strict_types = 1);

namespace JWX\Util;

/**
 * Class offering Base64 encoding and decoding.
 */
class Base64
{
    /**
     * Encode a string using base64url variant.
     *
     * @link https://en.wikipedia.org/wiki/Base64#URL_applications
     * @param string $data
     * @return string
     */
    public static function urlEncode(string $data): string
    {
        return strtr(rtrim(self::encode($data), "="), "+/", "-_");
    }
    
    /**
     * Decode a string using base64url variant.
     *
     * @link https://en.wikipedia.org/wiki/Base64#URL_applications
     * @param string $data
     * @throws \UnexpectedValueException
     * @return string
     */
    public static function urlDecode(string $data): string
    {
        $data = strtr($data, "-_", "+/");
        switch (strlen($data) % 4) {
            case 0:
                break;
            case 2:
                $data .= "==";
                break;
            case 3:
                $data .= "=";
                break;
            default:
                throw new \UnexpectedValueException(
                    "Malformed base64url encoding.");
        }
        return self::decode($data);
    }
    
    /**
     * Check whether string is validly base64url encoded.
     *
     * @link https://en.wikipedia.org/wiki/Base64#URL_applications
     * @param string $data
     * @return bool
     */
    public static function isValidURLEncoding(string $data): bool
    {
        return preg_match('#^[A-Za-z0-9\-_]*$#', $data) == 1;
    }
    
    /**
     * Encode a string in base64.
     *
     * @link https://tools.ietf.org/html/rfc4648#section-4
     * @param string $data
     * @throws \RuntimeException If encoding fails
     * @return string
     */
    public static function encode(string $data): string
    {
        $ret = @base64_encode($data);
        if (!is_string($ret)) {
            $err = error_get_last();
            $msg = isset($err) && __FILE__ == $err['file'] ? $err['message'] : null;
            throw new \RuntimeException($msg ?? "base64_encode() failed.");
        }
        return $ret;
    }
    
    /**
     * Decode a string from base64 encoding.
     *
     * @link https://tools.ietf.org/html/rfc4648#section-4
     * @param string $data
     * @throws \RuntimeException If decoding fails
     * @return string
     */
    public static function decode(string $data): string
    {
        $ret = base64_decode($data, true);
        if (!is_string($ret)) {
            $err = error_get_last();
            $msg = isset($err) && __FILE__ == $err['file'] ? $err['message'] : null;
            throw new \RuntimeException($msg ?? "base64_decode() failed.");
        }
        return $ret;
    }
    
    /**
     * Check whether string is validly base64 encoded.
     *
     * @link https://tools.ietf.org/html/rfc4648#section-4
     * @param string $data
     * @return bool
     */
    public static function isValid(string $data): bool
    {
        return preg_match('#^[A-Za-z0-9+/]*={0,2}$#', $data) == 1;
    }
}
