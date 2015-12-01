<?php


namespace PhpMiddleware\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\CredentialAdapter\UserPasswordInterface;
use Psr\Http\Message\ServerRequestInterface;
use UnexpectedValueException;

final class BasicAuthorizationService implements AuthorizationServiceInterface
{
    const AUTHORIZATION_HEADER = 'Authorization';
    const SCHEME = 'Basic';

    protected $adapter;
    protected $realm;

    public function __construct(UserPasswordInterface $adapter, $realm)
    {
        $this->adapter = $adapter;
        $this->realm = $realm;
    }

    public function authorize(ServerRequestInterface $request)
    {
        $header = $request->getHeaderLine(self::AUTHORIZATION_HEADER);

        list($username, $password) = $this->getCredentialsFromHeader($header);

        if ($username && $password) {
            $result = $this->adapter->authenticate($username, $password);

            if ($result === true) {
                return AuthorizationResult::authorized(self::SCHEME);
            } elseif ($result === false) {
                return AuthorizationResult::notAuthorized(self::SCHEME, [
                    'realm' => $this->realm,
                    'error' => 'Invalid credentials',
                    'error_description' => 'Login and/or password are invalid',
                ]);
            }
            throw new UnexpectedValueException(sprintf('%s\'s result must be a boolean value', UserPasswordInterface::class));
        }
        return AuthorizationResult::notAuthorized(self::SCHEME, [
            'realm' => $this->realm,
            'error' => '',
            'error_description' => '',
        ]);
    }

    private function getCredentialsFromHeader($header)
    {
        $matches = [];

        $userPass = $this->findBasicDecodedUserPassString($header);

        if (is_string($userPass) && preg_match('/^(?<username>[0-9a-z]+):(?<password>[0-9a-z]+)$/', $userPass, $matches) === 1) {
            return [
                $matches['username'],
                $matches['password']
            ];
        }
    }

    private function findBasicDecodedUserPassString($header)
    {
        $matches = [];

        if (preg_match('/^Basic (?<base64>(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)$/', $header, $matches) === 1) {
            $base64 = $matches['base64'];
            return base64_decode($base64);
        }
    }
}
