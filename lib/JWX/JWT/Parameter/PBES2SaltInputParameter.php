<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\Base64URLValue;

/**
 * Implements 'PBES2 Salt Input' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.8.1.1
 */
class PBES2SaltInputParameter extends JWTParameter
{
    use Base64URLValue;

    /**
     * Constructor.
     *
     * @param string $salt Base64url encoded salt input value
     */
    public function __construct(string $salt)
    {
        $this->_validateEncoding($salt);
        parent::__construct(self::PARAM_PBES2_SALT_INPUT, $salt);
    }

    /**
     * Get salt input value.
     *
     * @return string
     */
    public function saltInput(): string
    {
        return $this->string();
    }

    /**
     * Get computed salt value.
     *
     * @param AlgorithmParameter $algo
     *
     * @return string
     */
    public function salt(AlgorithmParameter $algo): string
    {
        return $algo->value() . "\0" . $this->saltInput();
    }
}
