<?php
namespace PHPOauth2\response;

use PHPOauth2\grant\AuthorizationCode;
use PHPContracts\oauth2\server\ResponseTypeInterface;

class ResponseCode implements ResponseTypeInterface
{
    const RESPONSE_TYPE = 'code';

    /**
     * @return string
     */
    public function getGrantType()
    {
        return AuthorizationCode::GRANT_TYPE;
    }
}