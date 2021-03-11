<?php
namespace PHPOauth2\grant;

use PHPOauth2\exception\InvalidAuthCodeExpcetion;
use PHPOauth2\exception\InvalidClientSecretException;
use PHPContracts\oauth2\server\entity\ClientEntityInterface;
use PHPContracts\oauth2\server\entity\UserEntityInterface;
use PHPContracts\oauth2\server\GrantTypeInterface;
use PHPContracts\oauth2\server\ServerInterface;

class AuthorizationCode implements GrantTypeInterface
{
    const GRANT_TYPE = 'AuthorizationCode';

    /**
     * @param  ServerInterface       $server
     * @param  UserEntityInterface   $userEntity
     * @param  ClientEntityInterface $clientEntity
     * @return string
     */
    public function handleAuthorizationRequest(ServerInterface $server, UserEntityInterface $userEntity, ClientEntityInterface $clientEntity) :string
    {
        $requestEntity  = $server->getRequestEntity();
        //创建授权码
        $authCodeEntity = $server->getAuthCodeFactory()->newAuthCode($requestEntity, $userEntity, $clientEntity);
        //持久化授权码
        $server->getAuthCodeRepository()->add($authCodeEntity);

        return $requestEntity->getRedirectUri().'?code='.$authCodeEntity->getCode().'&state='.$requestEntity->getState();
    }

    /**
     * @param  ServerInterface       $server
     * @param  ClientEntityInterface $clientEntity
     * @return array
     */
    public function handleTokenRequest(ServerInterface $server, ClientEntityInterface $clientEntity):array
    {
        $requestEntity  = $server->getRequestEntity();

        $clientId = $requestEntity->getAppId();
        //判断客户端密码是否正确
        if (!$clientEntity->validateSecret($requestEntity->getAppSecret())) {
            throw new InvalidClientSecretException();
        }
        //判断授权码是否存在
        if (!$authCodeEntity = $server->getAuthCodeRepository()->getByCode($requestEntity->getCode())) {
            throw new InvalidAuthCodeExpcetion();
        }
        //判断授权码是否过期
        if ($authCodeEntity->getExpireAt() < time()) {
            throw new InvalidAuthCodeExpcetion();
        }
        //判断授权码是否与客户端匹配
        if ($authCodeEntity->getClientId() != $clientId) {
            throw new InvalidAuthCodeExpcetion();
        }
        //判断授权码作用域
        $scope = $authCodeEntity->getScope();
        if (empty($scope)) {
            throw new InvalidAuthCodeExpcetion();
        }
        //判断用户是否存在
        if (!$userEntity = $server->getUserRepository()->getByUserId($authCodeEntity->getUserId())) {
            throw new InvalidAuthCodeExpcetion();
        }
        //创建Oauth2AccessTokenEntity
        $accessTokenEntity  = $server->getAccessTokenFactory()->newAccessToken($requestEntity, $userEntity, $clientEntity);
        //持久化Oauth2AccessTokenEntity
        $server->getAccessTokenRepository()->add($accessTokenEntity);
        //创建Oauth2refreshTokenEntity
        $refreshTokenEntity = $server->getRefreshTokenFactory()->newRefreshToken($requestEntity, $accessTokenEntity, $userEntity, $clientEntity);
        //持久化Oauth2refreshTokenEntity
        $server->getRefreshTokenRepository()->add($refreshTokenEntity);
        //删除Oauth2AuthCodeEntity
        $server->getAuthCodeRepository()->remove($authCodeEntity);

        return [
            'expiresIn'    => $accessTokenEntity->getExpireIn(),
            'accessToken'  => $accessTokenEntity->getAccessToken(),
            'refreshToken' => $refreshTokenEntity->getRefreshToken(),
            'userId'       => $userEntity->getUserId(),
            'scope'        => $requestEntity->getScope()
        ];
    }
}