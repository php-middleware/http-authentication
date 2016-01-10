<?php

namespace PhpMiddleware\HttpAuthentication\RequestBuilder;

use Psr\Http\Message\RequestInterface;

interface RequestBuilderInterface
{
    /**
     * @param RequestInterface $request
     *
     * @return RequestInterface
     */
    public function authenticate(RequestInterface $request);
}
