<?php

namespace PhpMiddlewareTest\HttpAuthentication\RequestBuilder;

use PhpMiddleware\HttpAuthentication\RequestBuilder\Basic;
use PHPUnit_Framework_TestCase;
use Psr\Http\Message\RequestInterface;
use Zend\Diactoros\Request;

class BasicTest extends PHPUnit_Framework_TestCase
{
    protected $requestBuilder;
    protected $request;

    protected function setUp()
    {
        $this->requestBuilder = new Basic('boo', 'foo');
        $this->request = new Request();
    }

    public function testRequestWithHeader()
    {
        $result = $this->requestBuilder->authenticate($this->request);

        $this->assertNotSame($this->request, $result);
        $this->assertInstanceOf(RequestInterface::class, $result);
        $this->assertSame('Basic Ym9vOmZvbwo=', $result->getHeaderLine('Authorization'));
    }
}
