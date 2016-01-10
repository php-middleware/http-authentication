<?php

namespace PhpMiddlewareTest\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\AuthorizationResultInterface;
use PhpMiddleware\HttpAuthentication\CredentialAdapter\ArrayUserPassword;
use PhpMiddleware\HttpAuthentication\DigestAuthorizationService;
use PHPUnit_Framework_TestCase;
use Zend\Diactoros\ServerRequest;

class DigestAuthorizationServiceTest extends PHPUnit_Framework_TestCase
{
    protected $service;
    protected $hashProvider;
    protected $serverRequest;

    protected function setUp()
    {
        $this->hashProvider = new ArrayUserPassword([
            'boo' => 'foo',
        ]);
        $this->service = new DigestAuthorizationService($this->hashProvider, 'realm');
        $this->serverRequest = new ServerRequest();
    }

    public function testNotAuthRequest()
    {
        $result = $this->service->authorize($this->serverRequest);

        $this->assertInstanceOf(AuthorizationResultInterface::class, $result);
        $this->assertFalse($result->isAuthorized());
    }

    public function testAuthRequest()
    {
        $header = 'Digest username="boo", realm="realm", nonce="nonce", uri="/boo/bar", response="13f87e6ef7f79c68f8721d3e6b9e45e5"';
        $request = $this->serverRequest->withHeader('Authorization', $header);

        $result = $this->service->authorize($request);

        $this->assertTrue($result->isAuthorized());
    }

    public function testNotAuthRequestWithoutRealm()
    {
        $header = 'Digest username="boo", nonce="nonce", uri="/boo/bar", response="13f87e6ef7f79c68f8721d3e6b9e45e5"';
        $request = $this->serverRequest->withHeader('Authorization', $header);

        $result = $this->service->authorize($request);

        $this->assertFalse($result->isAuthorized());
    }

    public function testNotAuthRequestRealmIsDifferent()
    {
        $header = 'Digest username="boo", realm="realmus", nonce="nonce", uri="/boo/bar", response="13f87e6ef7f79c68f8721d3e6b9e45e5"';
        $request = $this->serverRequest->withHeader('Authorization', $header);

        $result = $this->service->authorize($request);

        $this->assertFalse($result->isAuthorized());
    }

    public function testNotAuthRequestUsernameNotExists()
    {
        $header = 'Digest username="booz", realm="realm", nonce="nonce", uri="/boo/bar", response="13f87e6ef7f79c68f8721d3e6b9e45e5"';
        $request = $this->serverRequest->withHeader('Authorization', $header);

        $result = $this->service->authorize($request);

        $this->assertFalse($result->isAuthorized());
    }
}
