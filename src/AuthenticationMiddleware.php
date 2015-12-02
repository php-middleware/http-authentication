<?php

namespace PhpMiddleware\HttpAuthentication;

use PhpMiddleware\HttpAuthentication\Exception\MissingAuthorizationResult;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class AuthenticationMiddleware implements AuthorizationResultProviderInterface
{
    /**
     * @var AuthorizationServiceInterface
     */
    protected $service;

    /**
     * @var AuthorizationResultInterface
     */
    private $authorizationResult;

    /**
     * @param AuthorizationServiceInterface $service
     */
    public function __construct(AuthorizationServiceInterface $service)
    {
        $this->service = $service;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param callable $out
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $out)
    {
        $this->authorizationResult = $this->service->authorize($request);

        if (true === $this->authorizationResult->isAuthorized()) {
            $requestWithResult = $request->withAttribute(AuthorizationResultInterface::class, $this->authorizationResult);

            return $out($requestWithResult, $response);
        }

        $header = $this->buildWwwAuthenticateHeader($this->authorizationResult);

        return $response
                ->withStatus(401)
                ->withHeader('WWW-Authenticate', $header);
    }

    /**
     * @return AuthorizationResultInterface
     *
     * @throws MissingAuthorizationResult
     */
    public function getAuthorizationResult()
    {
        if ($this->authorizationResult === null) {
            throw new MissingAuthorizationResult('Middleware must be called first');
        }
        return $this->authorizationResult;
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