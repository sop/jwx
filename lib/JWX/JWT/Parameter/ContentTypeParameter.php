<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Content Type' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-4.1.10
 */
class ContentTypeParameter extends JWTParameter
{
    use StringParameterValue;

    /**
     * Content type for the nested JWT.
     *
     * @var string
     */
    public const TYPE_JWT = 'JWT';

    /**
     * Constructor.
     */
    public function __construct(string $type)
    {
        parent::__construct(self::PARAM_CONTENT_TYPE, $type);
    }
}
