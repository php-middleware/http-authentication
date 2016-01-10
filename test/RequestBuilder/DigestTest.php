<?php

namespace PhpMiddlewareTest\HttpAuthentication\RequestBuilder;

use PhpMiddleware\HttpAuthentication\RequestBuilder\Digest;
use PHPUnit_Framework_TestCase;
use Psr\Http\Message\RequestInterface;
use Zend\Diactoros\Request;
use Zend\Diactoros\Uri;

class DigestTest extends PHPUnit_Framework_TestCase
{
    protected $requestBuilder;
    protected $request;

    protected function setUp()
    {
        $this->requestBuilder = new Digest('boo', 'foo', 'realm', 'nonce');
        $uri = new Uri('/boo/bar');
        $this->request = new Request($uri, 'GET');
    }

    public function testAuthorizeRequest()
    {
        $result = $this->requestBuilder->authenticate($this->request);

        $this->assertNotSame($this->request, $result);
        $this->assertInstanceOf(RequestInterface::class, $result);
        $expected = 'Digest username="boo", realm="realm", nonce="nonce", uri="/boo/bar", response="13f87e6ef7f79c68f8721d3e6b9e45e5"';

        $this->assertSame($expected, $result->getHeaderLine('Authorization'));
    }
}
