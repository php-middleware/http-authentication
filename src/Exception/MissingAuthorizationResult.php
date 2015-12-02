<?php

namespace PhpMiddleware\HttpAuthentication\Exception;

class MissingAuthorizationResult extends \UnexpectedValueException
{
    public function __construct($message, \Exception $previous = null)
    {
        parent::__construct($message, null, $previous);
    }
}
