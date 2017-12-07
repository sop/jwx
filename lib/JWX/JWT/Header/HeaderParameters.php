<?php

declare(strict_types = 1);

namespace JWX\JWT\Header;

/**
 * Interface for classes providing JOSE header parameters.
 */
interface HeaderParameters
{
    /**
     * Get an array of JOSE header parameters representing this object.
     *
     * @return \JWX\JWT\Parameter\JWTParameter[]
     */
    public function headerParameters(): array;
}
