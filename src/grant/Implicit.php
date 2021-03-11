<?php
namespace PHPOauth2\grant;

use PHPOauth2\exception\UnsupportedMethodException;
use PHPContracts\oauth2\server\entity\ClientEntityInterface;
use PHPContracts\oauth2\server\entity\UserEntityInterface;
use PHPContracts\oauth2\server\GrantTypeInterface;
use PHPContracts\oauth2\server\ServerInterface;

class Implicit implements GrantTypeInterface
{
    const GRANT_TYPE = 'Implicit';

    /**
     * @param  ServerInterface       $server
     * @param  UserEntityInterface   $userEntity
     * @param  ClientEntityInterface $clientEntity
     * @return string
     */
    public function handleAuthorizationRequest(ServerInterface $server, UserEntityInterface $userEntity, ClientEntityInterface $clientEntity) :string
    {
        $requestEntity  = $server->getRequestEntity();
        //创建AccessToken
        $accessTokenEntity = $server->getAccessTokenFactory()->newAccessToken($requestEntity, $userEntity, $clientEntity);
        //持久化AccessToken
        $server->getAccessTokenRepository()->add($accessTokenEntity);

        return $requestEntity->getRedirectUri().'#access_token='.$accessTokenEntity->getAccessToken().'&state='.$requestEntity->getState();
    }

    /**
     * @param ServerInterface $server
     */
    public function handleTokenRequest(ServerInterface $server, ClientEntityInterface $clientEntity)
    {
        throw new UnsupportedMethodException();
    }
}