<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Encryption Algorithm' parameter for JWE headers.
 *
 * @see https://tools.ietf.org/html/rfc7516#section-4.1.2
 */
class EncryptionAlgorithmParameter extends JWTParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     *
     * @param string $algo Algorithm name
     */
    public function __construct(string $algo)
    {
        parent::__construct(self::PARAM_ENCRYPTION_ALGORITHM, $algo);
    }

    /**
     * Initialize from EncryptionAlgorithmParameterValue.
     *
     * @param EncryptionAlgorithmParameterValue $value
     *
     * @return self
     */
    public static function fromAlgorithm(
        EncryptionAlgorithmParameterValue $value): JWTParameter
    {
        return new self($value->encryptionAlgorithmParamValue());
    }
}
