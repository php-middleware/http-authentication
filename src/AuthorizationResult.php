<?php

namespace PhpMiddleware\HttpAuthentication;

final class AuthorizationResult implements AuthorizationResultInterface
{
    private $isAuthorized;

    private $challenge;

    private $scheme;

    private function __construct()
    {
    }

    public static function authorized($scheme, array $challenge = [])
    {
        $instance = new self();
        $instance->isAuthorized = true;
        $instance->scheme = $scheme;
        $instance->challenge = $challenge;

        return $instance;
    }

    public static function notAuthorized($scheme, array $challenge = [])
    {
        $instance = new self();
        $instance->isAuthorized = false;
        $instance->scheme = $scheme;
        $instance->challenge = $challenge;

        return $instance;
    }

    public function getChallenge()
    {
        return $this->challenge;
    }

    public function getScheme()
    {
        return $this->scheme;
    }

    public function isAuthorized()
    {
        return $this->isAuthorized;
    }

    public function getRequestAttributes()
    {
        // TODO: Implement getRequestAttributes() method.
    }
}
