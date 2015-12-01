<?php

namespace PhpMiddleware\HttpAuthentication;

final class AuthorizationResult implements AuthorizationResultInterface
{
    /**
     * @var bool
     */
    private $isAuthorized;

    /**
     * @var array
     */
    private $challenge;

    /**
     * @var string
     */
    private $scheme;

    /**
     * @var array
     */
    private $attributes;

    private function __construct()
    {
    }

    /**
     * @param string $scheme
     * @param array $challenge
     * @param array $attributes
     *
     * @return self
     */
    public static function authorized($scheme, array $challenge = [], array $attributes = [])
    {
        $instance = new self();
        $instance->isAuthorized = true;
        $instance->scheme = $scheme;
        $instance->challenge = $challenge;
        $instance->attributes = $attributes;

        return $instance;
    }

    /**
     * @param string $scheme
     * @param array $challenge
     * @param array $attributes
     *
     * @return self
     */
    public static function notAuthorized($scheme, array $challenge = [], array $attributes = [])
    {
        $instance = new self();
        $instance->isAuthorized = false;
        $instance->scheme = $scheme;
        $instance->challenge = $challenge;
        $instance->attributes = $attributes;

        return $instance;
    }

    /**
     * @return array
     */
    public function getChallenge()
    {
        return $this->challenge;
    }

    /**
     * @return string
     */
    public function getScheme()
    {
        return $this->scheme;
    }

    /**
     * @return bool
     */
    public function isAuthorized()
    {
        return $this->isAuthorized;
    }

    /**
     * @return array
     */
    public function getAttributes()
    {
        return $this->attributes;
    }
}
