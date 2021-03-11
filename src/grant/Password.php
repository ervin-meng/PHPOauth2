<?php
namespace PHPOauth2\grant;

use PHPOauth2\exception\InvalidDefaultScopeException;
use PHPOauth2\exception\InvalidUserException;
use PHPOauth2\exception\UnsupportedMethodException;
use PHPContracts\oauth2\server\entity\ClientEntityInterface;
use PHPContracts\oauth2\server\entity\UserEntityInterface;
use PHPContracts\oauth2\server\GrantTypeInterface;
use PHPContracts\oauth2\server\ServerInterface;

class Password implements GrantTypeInterface
{
    const GRANT_TYPE = 'Password';

    /**
     * @param  ServerInterface       $server
     * @param  UserEntityInterface   $userEntity
     * @param  ClientEntityInterface $clientEntity
     */
    public function handleAuthorizationRequest(ServerInterface $server, UserEntityInterface $userEntity, ClientEntityInterface $clientEntity)
    {
        throw new UnsupportedMethodException();
    }

    /**
     * @param  ServerInterface       $server
     * @param  ClientEntityInterface $clientEntity
     * @return array
     */
    public function handleTokenRequest(ServerInterface $server, ClientEntityInterface $clientEntity):array
    {
        $requestEntity = $server->getRequestEntity();
        //判断用户默认授权域
        if (empty($server->getDefaultScope())) {
            throw new InvalidDefaultScopeException();
        }
        $requestEntity->setScope($server->getDefaultScope());
        //判断用户名和密码是否正确
        if (!$userEntity = $server->getUserRepository()->getByNameAndPassword($requestEntity->getUserName(), $requestEntity->getPassword())) {
            throw new InvalidUserException();
        }
        //创建Oauth2AccessTokenEntity
        $accessTokenEntity = $server->getAccessTokenFactory()->newAccessToken($requestEntity, $userEntity, $clientEntity);
        //持久化Oauth2AccessTokenEntity
        $server->getAccessTokenRepository()->add($accessTokenEntity);
        //创建Oauth2refreshTokenEntity
        $refreshTokenEntity = $server->getRefreshTokenFactory()->newRefreshToken($requestEntity, $accessTokenEntity, $userEntity, $clientEntity);
        //持久化Oauth2refreshTokenEntity
        $server->getRefreshTokenRepository()->add($refreshTokenEntity);

        return [
            'expiresIn'    => $accessTokenEntity->getExpireIn(),
            'accessToken'  => $accessTokenEntity->getAccessToken(),
            'refreshToken' => $refreshTokenEntity->getRefreshToken(),
            'userId'       => $userEntity->getUserId()
        ];
    }
}