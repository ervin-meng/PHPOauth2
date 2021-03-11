<?php
namespace PHPOauth2\response;

use PHPOauth2\grant\Implicit;
use PHPContracts\oauth2\server\ResponseTypeInterface;

class ResponseToken implements ResponseTypeInterface
{
    const RESPONSE_TYPE = 'token';

    /**
     * @return string
     */
    public function getGrantType()
    {
        return Implicit::GRANT_TYPE;
    }
}