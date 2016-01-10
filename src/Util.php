<?php

namespace PhpMiddleware\HttpAuthentication;

final class Util
{
    /**
     * @codeCoverageIgnore
     */
    private function __construct()
    {
    }

    /**
     * @param array $params
     *
     * @return string md5
     */
    public static function md5Implode(array $params)
    {
        return md5(implode(':', $params));
    }

    /**
     * @param string $scheme
     * @param array $challenges
     *
     * @return string
     */
    public static function buildHeader($scheme, array $challenges)
    {
        $challenge = self::buildChallengeString($challenges);

        if (empty($challenge)) {
            return $scheme;
        }

        return sprintf('%s %s', $scheme, $challenge);
    }

    /**
     * @param array $serviceChallenge
     *
     * @return string
     */
    private static function buildChallengeString(array $serviceChallenge)
    {
        $challengePairs = [];

        foreach ($serviceChallenge as $challenge => $value) {
            $challengePairs[] = sprintf('%s="%s"', $challenge, addslashes($value));
        }
        return implode(', ', $challengePairs);
    }
}
