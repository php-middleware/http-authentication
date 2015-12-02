<?php

namespace PhpMiddleware\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\Exception\MissingAuthorizationResult;

interface AutorizationResultProviderInterface
{
    /**
     * @return AuthorizationResultInterface
     *
     * @throws MissingAuthorizationResult
     */
    public function getAuthorizationResult();
}
