<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Feature\ArrayParameterValue;

/**
 * Implements 'Key Operations' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4.3
 */
class KeyOperationsParameter extends JWKParameter
{
    use ArrayParameterValue;

    public const OP_SIGN = 'sign';
    public const OP_VERIFY = 'verify';
    public const OP_ENCRYPT = 'encrypt';
    public const OP_DECRYPT = 'decrypt';
    public const OP_WRAP_KEY = 'wrapKey';
    public const OP_UNWRAP_KEY = 'unwrapKey';
    public const OP_DERIVE_KEY = 'deriveKey';
    public const OP_DERIVE_BITS = 'deriveBits';

    /**
     * Constructor.
     *
     * @param string ...$ops Key operations
     */
    public function __construct(string ...$ops)
    {
        parent::__construct(self::PARAM_KEY_OPERATIONS, $ops);
    }
}
