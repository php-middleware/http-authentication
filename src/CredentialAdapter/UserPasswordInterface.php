<?php

namespace PhpMiddleware\HttpAuthentication\CredentialAdapter;

interface UserPasswordInterface
{
    public function authenticate($username, $password);
}
