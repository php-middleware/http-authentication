<?php

namespace PhpMiddlewareTest\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\BasicAuthorizationService;
use PhpMiddleware\HttpAuthentication\CredentialAdapter\UserPasswordInterface;
use PHPUnit_Framework_TestCase;
use Psr\Http\Message\ServerRequestInterface;

class BasicAuthorizationServiceTest extends PHPUnit_Framework_TestCase
{
    protected $service;
    protected $adapter;
    protected $realm = 'BarBoo';
    protected $request;

    protected function setUp()
    {
        $this->adapter = $this->getMock(UserPasswordInterface::class);
        $this->service = new BasicAuthorizationService($this->adapter, $this->realm);
        $this->request = $this->getMock(ServerRequestInterface::class);
    }

    public function testNotAuthDataInRequest()
    {
        $result = $this->service->authorize($this->request);

        $this->assertFalse($result->isAuthorized());
        $this->assertSame(BasicAuthorizationService::SCHEME, $result->getScheme());
    }

    public function testAuthorize()
    {
        $this->request->expects($this->once())->method('getHeaderLine')->with('Authorization')->willReturn('Basic Ym9vOmZvbw==');
        $this->adapter->expects($this->once())->method('authenticate')->willReturn(true);
        $result = $this->service->authorize($this->request);

        $this->assertTrue($result->isAuthorized());
        $this->assertSame(BasicAuthorizationService::SCHEME, $result->getScheme());
    }

    public function testNotAuthorize()
    {
        $this->request->expects($this->once())->method('getHeaderLine')->with('Authorization')->willReturn('Basic Ym9vOmZvbw==');
        $this->adapter->expects($this->once())->method('authenticate')->willReturn(false);
        $result = $this->service->authorize($this->request);

        $this->assertFalse($result->isAuthorized());
        $challenge = $result->getChallenge();
        $this->assertSame(BasicAuthorizationService::SCHEME, $result->getScheme());
        $this->assertArrayHasKey('realm', $challenge);
        $this->assertSame($this->realm, $challenge['realm']);
    }

    public function testInvalidAdapterResult()
    {
        $this->setExpectedException(\UnexpectedValueException::class);

        $this->request->expects($this->once())->method('getHeaderLine')->with('Authorization')->willReturn('Basic Ym9vOmZvbw==');
        $this->adapter->expects($this->once())->method('authenticate');
        $result = $this->service->authorize($this->request);

        $result->isAuthorized();
    }
}
