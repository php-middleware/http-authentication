<?php

namespace PhpMiddlewareTest\HttpAuthentication\CredentialAdapter;

use PhpMiddleware\HttpAuthentication\CredentialAdapter\ArrayUserPassword;
use PhpMiddleware\HttpAuthentication\CredentialAdapter\Exception\UsernameNotFoundException;
use PHPUnit_Framework_TestCase;

class ArrayUserPasswordTest extends PHPUnit_Framework_TestCase
{
    protected $adapter;
    protected $users = [
        'boo' => 'bar',
        'bar' => 'foo',
    ];

    protected function setUp()
    {
        $this->adapter = new ArrayUserPassword($this->users);
    }

    /**
     * @dataProvider correctDataProvider
     */
    public function testAuthenticate($username, $password)
    {
        $result = $this->adapter->authenticate($username, $password);

        $this->assertTrue($result);
    }

    /**
     * @dataProvider incorrectDataProvider
     */
    public function testNotAuthenticate($username, $password)
    {
        $result = $this->adapter->authenticate($username, $password);

        $this->assertFalse($result);
    }

    public function testGetHash()
    {
        $result = $this->adapter->getHash('boo', 'any-realm');

        $this->assertSame(32, strlen($result));
    }

    public function testInvalidUsername()
    {
        $this->setExpectedException(UsernameNotFoundException::class);

        $this->adapter->getHash('baz', 'any-realm');
    }

    public function correctDataProvider()
    {
        return [
            ['boo', 'bar'],
            ['bar', 'foo'],
        ];
    }

    public function incorrectDataProvider()
    {
        return [
            ['bar', 'boo'],
            ['bar', null],
            ['bar', false],
            [null, false],
        ];
    }
}
