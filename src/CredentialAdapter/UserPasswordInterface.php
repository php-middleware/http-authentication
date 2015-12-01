<?php

namespace PhpMiddleware\HttpAuthentication\CredentialAdapter;

interface UserPasswordInterface
{
    /**
     * @param mixed $username
     * @param mixed $password
     *
     * @return bool
     */
    public function authenticate($username, $password);
}
