<?php

namespace PhpMiddlewareTest\HttpAuthentication\CredentialAdapter;

use PhpMiddleware\HttpAuthentication\CredentialAdapter\ArrayUserPassword;
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
