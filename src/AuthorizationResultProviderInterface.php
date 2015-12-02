<?php

namespace PhpMiddleware\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\Exception\MissingAuthorizationResult;

interface AuthorizationResultProviderInterface
{
    /**
     * @return AuthorizationResultInterface
     *
     * @throws MissingAuthorizationResult
     */
    public function getAuthorizationResult();
}
