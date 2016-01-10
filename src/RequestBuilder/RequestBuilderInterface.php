<?php

namespace PhpMiddleware\HttpAuthentication\RequestBuilder;

use Psr\Http\Message\RequestInterface;

interface RequestBuilderInterface
{
    public function authenticate(RequestInterface $request);
}
