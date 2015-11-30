<?php

namespace PhpMiddleware\HttpAuthentication;

use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationServiceInterface
{
    /**
     * @param ServerRequestInterface $request
     *
     * @return AuthorizationResultInterface
     */
    public function authorize(ServerRequestInterface $request);
}
