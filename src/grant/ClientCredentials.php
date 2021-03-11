<?php
namespace PHPOauth2\grant;

use PHPOauth2\exception\InvalidClientSecretException;
use PHPOauth2\exception\InvalidDefaultScopeException;
use PHPOauth2\exception\UnsupportedMethodException;
use PHPContracts\oauth2\server\entity\ClientEntityInterface;
use PHPContracts\oauth2\server\entity\UserEntityInterface;
use PHPContracts\oauth2\server\GrantTypeInterface;
use PHPContracts\oauth2\server\ServerInterface;

class ClientCredentials implements GrantTypeInterface
{
    const GRANT_TYPE = 'ClientCredentials';

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
     * @param  ServerInterface $server
     * @return array
     */
    public function handleTokenRequest(ServerInterface $server, ClientEntityInterface $clientEntity):array
    {
        $requestEntity = $server->getRequestEntity();
        //判断客户端密码是否正确
        if (!$clientEntity->validateSecret($requestEntity->getAppSecret())) {
            throw new InvalidClientSecretException();
        }
        //判断客户端默认授权域
        $scope = $server->getDefaultScope();
        if (empty($scope)) {
            $scope = $clientEntity->getScope();
            if (empty($scope)){
                throw new InvalidDefaultScopeException();
            }
        }
        $requestEntity->setScope($scope);
        //创建Oauth2AccessTokenEntity
        $accessTokenEntity  = $server->getAccessTokenFactory()->newAccessToken($requestEntity, null, $clientEntity);
        //持久化Oauth2AccessTokenEntity
        $server->getAccessTokenRepository()->add($accessTokenEntity);
        //创建Oauth2refreshTokenEntity
        $refreshTokenEntity = $server->getRefreshTokenFactory()->newRefreshToken($requestEntity, $accessTokenEntity, null, $clientEntity);
        //持久化Oauth2refreshTokenEntity
        $server->getRefreshTokenRepository()->add($refreshTokenEntity);

        return [
            'expiresIn'    => $accessTokenEntity->getExpireIn(),
            'accessToken'  => $accessTokenEntity->getAccessToken(),
            'refreshToken' => $refreshTokenEntity->getRefreshToken(),
        ];
    }
}