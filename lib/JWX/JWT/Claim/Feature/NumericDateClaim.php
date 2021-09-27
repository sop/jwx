<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim\Feature;

/**
 * Trait for claims having NumericDate value.
 */
trait NumericDateClaim
{
    /**
     * Constructor.
     *
     * @param int $timestamp Unix timestamp
     */
    abstract public function __construct(int $timestamp);

    /**
     * Get the parameter value.
     *
     * @return string
     */
    abstract public function value();

    /**
     * Initialize instance from date/time string.
     *
     * @param string $time `strtotime` compatible time string
     * @param string $tz   Default timezone
     *
     * @throws \RuntimeException
     *
     * @return static
     */
    public static function fromString(string $time, string $tz = 'UTC')
    {
        try {
            $dt = new \DateTimeImmutable($time, self::_createTimeZone($tz));
            return new static($dt->getTimestamp());
        } catch (\Exception $e) {
            throw new \RuntimeException(
                'Failed to create DateTime: ' .
                     self::_getLastDateTimeImmutableErrorsStr(), 0, $e);
        }
    }

    /**
     * Get date as a unix timestamp.
     */
    public function timestamp(): int
    {
        return (int) $this->value();
    }

    /**
     * Get date as a datetime object.
     *
     * @param string $tz Timezone
     *
     * @throws \RuntimeException
     */
    public function dateTime(string $tz = 'UTC'): \DateTimeImmutable
    {
        $dt = \DateTimeImmutable::createFromFormat('!U', strval($this->value()),
            self::_createTimeZone($tz));
        if (false === $dt) {
            throw new \RuntimeException(
                'Failed to create DateTime: ' .
                     self::_getLastDateTimeImmutableErrorsStr());
        }
        return $dt;
    }

    /**
     * Create DateTimeZone object from string.
     *
     * @throws \UnexpectedValueException
     */
    private static function _createTimeZone(string $tz): \DateTimeZone
    {
        try {
            return new \DateTimeZone($tz);
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Invalid timezone.', 0, $e);
        }
    }

    /**
     * Get last error caused by DateTimeImmutable.
     */
    private static function _getLastDateTimeImmutableErrorsStr(): string
    {
        $errors = \DateTimeImmutable::getLastErrors()['errors'];
        return implode(', ', $errors);
    }
}
