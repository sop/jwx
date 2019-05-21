<?php

declare(strict_types = 1);

use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Claim\Validator\EqualsValidator;
use Sop\JWX\JWT\JWT;
use Sop\JWX\JWT\ValidationContext;

require dirname(__DIR__) . '/vendor/autoload.php';

// HS512 example token from https://jwt.io/#debugger-io
$token = <<<'EOF'
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.
VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg
EOF;
$token = preg_replace('/\s/', '', $token);

// EXAMPLE 1: Simple validation
$jwt = new JWT($token);
// create context for the claims validation
// 'your-512-bit-secret' key is used to verify the signature
$ctx = ValidationContext::fromJWK(
    SymmetricKeyJWK::fromKey('your-512-bit-secret'));
// validate claims
$claims = $jwt->claims($ctx);
// print value of the subject claim
echo $claims->subject()->value() . "\n";

// EXAMPLE 2: Additional validation
$jwt = new JWT($token);
// validate that the subject is "1234567890"
// validate that the admin claim is true using explicitly provided validator
$ctx = ValidationContext::fromJWK(
    SymmetricKeyJWK::fromKey('your-512-bit-secret'),
        ['sub' => '1234567890']
    )->withConstraint('admin', true, new EqualsValidator());
// validate and print all claims
$claims = $jwt->claims($ctx);
foreach ($claims as $claim) {
    printf("%s: %s\n", $claim->name(), $claim->value());
}
