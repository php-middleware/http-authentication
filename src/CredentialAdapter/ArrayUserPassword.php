<?php

namespace PhpMiddleware\HttpAuthentication\CredentialAdapter;

use PhpMiddleware\HttpAuthentication\CredentialAdapter\Exception\UsernameNotFoundException;
use PhpMiddleware\HttpAuthentication\Util;

final class ArrayUserPassword implements UserPasswordInterface, HashProviderInterface
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
        return $this->isUserNameExists($username) && $this->users[$username] === $password;
    }

    private function isUserNameExists($username)
    {
        return isset($this->users[$username]);
    }

    public function getHash($username, $realm)
    {
        if (!$this->isUserNameExists($username)) {
            throw new UsernameNotFoundException('Username does not exist');
        }
        return Util::md5Implode([
            $username,
            $realm,
            $this->users[$username],
        ]);
    }

}
