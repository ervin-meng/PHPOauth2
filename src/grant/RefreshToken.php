<?php
namespace PHPOauth2\grant;

use PHPOauth2\exception\InvalidClientSecretException;
use PHPOauth2\exception\InvalidRefreshTokenException;
use PHPOauth2\exception\UnsupportedMethodException;
use PHPContracts\oauth2\server\entity\ClientEntityInterface;
use PHPContracts\oauth2\server\entity\UserEntityInterface;
use PHPContracts\oauth2\server\GrantTypeInterface;
use PHPContracts\oauth2\server\ServerInterface;

class RefreshToken implements GrantTypeInterface
{
    const GRANT_TYPE = 'RefreshToken';

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
     * @param  ServerInterface        $server
     * @param  ClientEntityInterface  $clientEntity
     * @return array
     */
    public function handleTokenRequest(ServerInterface $server, ClientEntityInterface $clientEntity):array
    {
        $requestEntity = $server->getRequestEntity();

        //判断refreshToken是否存在
        if (!$refreshTokenEntity = $server->getRefreshTokenRepository()->getByToken($requestEntity->getRefreshToken())) {
            throw new InvalidRefreshTokenException();
        }
        //判断refreshToken是否过期
        if ($refreshTokenEntity->getCreateTime() + $refreshTokenEntity->getExpireIn() < time()) {
            throw new InvalidRefreshTokenException();
        }
        //判断refreshToken是否被授权当前客户端
        if ($refreshTokenEntity->getClientId() != $requestEntity->getAppId()) {
            throw new InvalidRefreshTokenException();
        }
        //判断refreshToken授权作用域是否为空
        if(!$scope = $refreshTokenEntity->getScope()) {
            throw new InvalidRefreshTokenException();
        }
        //判断客户端密码是否存在
        if (!$clientEntity->validateSecret($requestEntity->getAppSecret())) {
            throw new InvalidClientSecretException();
        }
        //判断客户端授权域是否被撤销
        if(!$clientEntity->validateScope($scope)){
            throw new InvalidRefreshTokenException();
        }
        //判断授权用户是否存在
        if ($userId = $refreshTokenEntity->getUserId()) {
            if (!$userEntity = $server->getUserRepository()->getByUserId($userId)) {
                throw new InvalidRefreshTokenException();
            }
        } else {
            $userEntity = null;
        }
        //创建新的Oauth2AccessTokenEntity
        $accessTokenEntity  = $server->getAccessTokenFactory()->newAccessToken($requestEntity, $userEntity, $clientEntity, $refreshTokenEntity);
        //持久化新的Oauth2AccessTokenEntity
        $server->getAccessTokenRepository()->add($accessTokenEntity);
        //回收旧的Oauth2AccessTokenEntity
        $accessTokenId = $refreshTokenEntity->getAccessTokenId();
        $server->getAccessTokenRepository()->removeById($accessTokenId);
        //TODO 是否重新生成refreshToken
        if (false) {
            $refreshTokenRepository = $server->getRefreshTokenRepository();
            //删除之前的Oauth2refreshTokenEntity
            $refreshTokenRepository->remove($refreshTokenEntity);
            //创建新的Oauth2refreshTokenEntity
            $refreshTokenEntity = $server->getRefreshTokenFactory()->newRefreshToken($requestEntity, $accessTokenEntity, $userEntity, $clientEntity);
            //持久化新的Oauth2refreshTokenEntity
            $refreshTokenRepository->add($refreshTokenEntity);
        }

        return [
            'expiresIn'    => $accessTokenEntity->getExpireIn(),
            'accessToken'  => $accessTokenEntity->getAccessToken(),
            'refreshToken' => $refreshTokenEntity->getRefreshToken(),
            'userId'       => $refreshTokenEntity->getUserId()
        ];
    }
}