<?php

namespace PhpMiddleware\HttpAuthentication;

interface AuthorizationResultInterface
{
    /**
     * @return bool
     */
    public function isAuthorized();

    /**
     * @return string
     */
    public function getScheme();

    /**
     * @return array
     */
    public function getChallenge();
}
