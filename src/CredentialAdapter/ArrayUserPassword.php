<?php

namespace PhpMiddleware\HttpAuthentication\CredentialAdapter;

final class ArrayUserPassword implements UserPasswordInterface
{
    /**
     * @var array
     */
    protected $users;

    /**
     * @param array $users
     */
    public function __construct(array $users)
    {
        $this->users = $users;
    }

    /**
     * @param mixed $username
     * @param mixed $password
     *
     * @return bool
     */
    public function authenticate($username, $password)
    {
        return isset($this->users[$username]) && $this->users[$username] === $password;
    }
}
