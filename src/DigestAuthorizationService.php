<?php


namespace PhpMiddleware\HttpAuthentication;

use Psr\Http\Message\ServerRequestInterface;

final class DigestAuthorizationService implements AuthorizationServiceInterface
{
    public function authorize(ServerRequestInterface $request)
    {
        throw new \BadMethodCallException('Not implemented');
    }
}
