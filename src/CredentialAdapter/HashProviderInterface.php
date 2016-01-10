<?php

namespace PhpMiddleware\HttpAuthentication\CredentialAdapter;

interface HashProviderInterface
{
    public function getHash($username, $realm);
}
