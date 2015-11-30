<?php

namespace PhpMiddleware\HttpAuthentication;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class AuthenticationMiddleware
{
    protected $service;

    public function __construct(AuthorizationServiceInterface $service)
    {
        $this->service = $service;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $out)
    {
        $result = $this->service->authorize($request);

        if (true === $result->isAuthorized()) {
            return $out($request, $response);
        }

        $header = $this->buildWwwAuthenticateHeader($result);

        return $response
                ->withStatus(401)
                ->withHeader('WWW-Authenticate', $header);
    }

    /**
     * @param AuthorizationResultInterface $result
     *
     * @return string
     */
    private function buildWwwAuthenticateHeader(AuthorizationResultInterface $result)
    {
        $scheme = $result->getScheme();
        $challenge = $this->buildChallengeString($result->getChallenge());

        if (empty($challenge)) {
            return $scheme;
        }

        return sprintf('%s %s', $scheme, $challenge);
    }

    /**
     * @param array $serviceChallenge
     *
     * @return type
     */
    private function buildChallengeString(array $serviceChallenge)
    {
        $challengePairs = [];

        foreach ($serviceChallenge as $challenge => $value) {
            $challengePairs[] = sprintf('%s="%s"', $challenge, addslashes($value));
        }
        return implode(', ', $challengePairs);
    }
}