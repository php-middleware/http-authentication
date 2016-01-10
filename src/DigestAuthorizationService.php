<?php

namespace PhpMiddleware\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\CredentialAdapter\Exception\UsernameNotFoundException;
use PhpMiddleware\HttpAuthentication\CredentialAdapter\HashProviderInterface;
use Psr\Http\Message\ServerRequestInterface;

final class DigestAuthorizationService implements AuthorizationServiceInterface
{
    private $hashProvider;
    private $realm;

    public function __construct(HashProviderInterface $hashProvider, $realm)
    {
        $this->hashProvider = $hashProvider;
        $this->realm = $realm;
    }

    public function authorize(ServerRequestInterface $request)
    {
        $header = $request->getHeaderLine('Authorization');

        $authorization = $this->parseAuthorizationHeader($header);

        if (!$authorization) {
            return AuthorizationResult::error('digest', 'Invalid header', 'Cannot read data from Authorization header', [
                'realm' => $this->realm,
            ]);
        }

        $result = $this->checkAuthentication($authorization, $request->getMethod());

        if ($result) {
            return AuthorizationResult::authorized('digest');
        }
        return AuthorizationResult::notAuthorized('digest', [], $authorization);
    }

    private function checkAuthentication(array $authorization, $method)
    {
        if ($authorization['realm'] !== $this->realm) {
            return false;
        }
        try {
            $A1 = $this->hashProvider->getHash($authorization['username'], $this->realm);
        } catch (UsernameNotFoundException $exception) {
            return false;
        }

        $A2 = Util::md5Implode([$method, $authorization['uri']]);

        $realResponse = Util::md5Implode([$A1, $authorization['nonce'], $A2]);

        return $authorization['response'] === $realResponse;
    }

    private function parseAuthorizationHeader($header)
    {
        if (strpos($header, 'Digest') !== 0) {
            return false;
        }

        $neededParts = ['nonce' => 1, 'realm' => 1, 'username' => 1, 'uri' => 1, 'response' => 1];
        $neededPartsString = implode('|', array_keys($neededParts));
        $data = [];

        preg_match_all('@('.$neededPartsString.')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', substr($header, 7), $matches, PREG_SET_ORDER);

        if (is_array($matches)) {
            foreach ($matches as $match) {
                $data[$match[1]] = $match[3] ?: $match[4];
                unset($neededParts[$match[1]]);
            }
        }

        if (!empty($neededParts)) {
            return false;
        }

        return $data;
    }
}
