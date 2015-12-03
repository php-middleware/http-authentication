<?php

namespace PhpMiddlewareTest\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\BasicAuthorizationService;
use PhpMiddleware\HttpAuthentication\CredentialAdapter\UserPasswordInterface;
use PHPUnit_Framework_TestCase;
use Psr\Http\Message\ServerRequestInterface;

class BasicAuthorizationServiceTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var BasicAuthorizationService
     */
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
        $this->assertSame('Basic', $result->getScheme());
    }

    /**
     * @dataProvider getValidUserPassProvider
     */
    public function testSuccessfulAuthorization($userPass)
    {
        $base64UserPass = base64_encode($userPass);

        $this->request->expects($this->once())->method('getHeaderLine')->with('Authorization')->willReturn("Basic {$base64UserPass}");
        $this->adapter->expects($this->once())->method('authenticate')->willReturn(true);
        $result = $this->service->authorize($this->request);

        $this->assertTrue($result->isAuthorized());
        $this->assertSame('Basic', $result->getScheme());
        $this->assertArrayHasKey('user-ID', $result->getAttributes());
    }

    public function testUnsuccessfulAuthorization()
    {
        $this->request->expects($this->once())->method('getHeaderLine')->with('Authorization')->willReturn('Basic Ym9vOmZvbw==');
        $this->adapter->expects($this->once())->method('authenticate')->willReturn(false);
        $result = $this->service->authorize($this->request);

        $this->assertFalse($result->isAuthorized());
        $challenge = $result->getChallenge();
        $this->assertSame('Basic', $result->getScheme());
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

    public function getValidUserPassProvider()
    {
        return [
            ['boo:foo'],
            ['Boo1:Foo2'],
        ];
    }
}
