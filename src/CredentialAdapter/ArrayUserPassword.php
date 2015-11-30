<?php

namespace PhpMiddleware\HttpAuthentication\CredentialAdapter;

final class ArrayUserPassword implements UserPasswordInterface
{
    protected $users;

    public function __construct(array $users)
    {
        $this->users = $users;
    }

    public function authenticate($username, $password)
    {
        return isset($this->users[$username]) && $this->users[$username] === $password;
    }

}
