<?php

namespace PhpMiddleware\HttpAuthentication\RequestBuilder;

use PhpMiddleware\HttpAuthentication\Util;
use Psr\Http\Message\RequestInterface;

/**
 * @link https://tools.ietf.org/html/rfc2069
 */
final class Digest implements RequestBuilderInterface
{
    private $username;
    private $password;
    private $realm;
    private $nonce;

    public function __construct($username, $password, $realm, $nonce)
    {
        $this->username = $username;
        $this->password = $password;
        $this->realm = $realm;
        $this->nonce = $nonce;
    }

    /**
     * @param RequestInterface $request
     *
     * @return RequestInterface
     */
    public function authenticate(RequestInterface $request)
    {
        $uri = (string) $request->getUri();

        $a1 = Util::md5Implode([$this->username, $this->realm, $this->password]);
        $a2 = Util::md5Implode([$request->getMethod(), $uri]);

        $response = Util::md5Implode([$a1, $this->nonce, $a2]);

        $value = Util::buildHeader('Digest', [
            'username' => $this->username,
            'realm' => $this->realm,
            'nonce' => $this->nonce,
            'uri' => $uri,
            'response' => $response,
        ]);

        return $request->withHeader('Authorization', $value);
    }
}
