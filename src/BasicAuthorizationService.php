<?php


namespace PhpMiddleware\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\CredentialAdapter\UserPasswordInterface;
use Psr\Http\Message\ServerRequestInterface;
use UnexpectedValueException;

final class BasicAuthorizationService implements AuthorizationServiceInterface
{
    const AUTHORIZATION_HEADER = 'Authorization';
    const SCHEME = 'Basic';

    /**
     * @var UserPasswordInterface
     */
    protected $adapter;

    /**
     * @var string
     */
    protected $realm;

    /**
     * @param UserPasswordInterface $adapter
     * @param string $realm
     */
    public function __construct(UserPasswordInterface $adapter, $realm)
    {
        $this->adapter = $adapter;
        $this->realm = (string) $realm;
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @return AuthorizationResultInterface
     *
     * @throws UnexpectedValueException
     */
    public function authorize(ServerRequestInterface $request)
    {
        $header = $request->getHeaderLine(self::AUTHORIZATION_HEADER);

        list($userId, $password) = $this->findCredentialsFromHeader($header);

        if ($userId && $password) {
            $result = $this->adapter->authenticate($userId, $password);

            if ($result === true) {
                return AuthorizationResult::authorized(self::SCHEME, [], ['user-ID' => $userId]);
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

    /**
     * @param string $header
     *
     * @return array|null
     */
    private function findCredentialsFromHeader($header)
    {
        $matches = [];

        $userPass = $this->findBasicDecodedUserPassString($header);

        if (is_string($userPass) && preg_match('/^(?<userID>[0-9a-zA-Z]+):(?<password>[0-9a-zA-Z]+)$/', $userPass, $matches) === 1) {
            return [
                $matches['userID'],
                $matches['password']
            ];
        }
    }

    /**
     * @param string $header
     *
     * @return string|null
     */
    private function findBasicDecodedUserPassString($header)
    {
        $matches = [];

        if (preg_match('/^Basic (?<base64>(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)$/', $header, $matches) === 1) {
            $base64 = $matches['base64'];

            return base64_decode($base64);
        }
    }
}
