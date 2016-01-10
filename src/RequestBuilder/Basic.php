<?php

namespace PhpMiddleware\HttpAuthentication\RequestBuilder;

use Psr\Http\Message\RequestInterface;

final class Basic implements RequestBuilderInterface
{
    private $user;
    private $password;

    public function __construct($user, $password)
    {
        $this->user = $user;
        $this->password = $password;
    }

    /**
     * @param RequestInterface $request
     *
     * @return RequestInterface New instance with Authorization header
     */
    public function authenticate(RequestInterface $request)
    {
        $base64 = base64_encode(sprintf('%s:%s', $this->user, $this->password));

        $value = sprintf('Basic %s', $base64);

        return $request->withHeader('Authorization', $value);
    }
}
