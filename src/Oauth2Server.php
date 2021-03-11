<?php
namespace PHPOauth2;

use PHPOauth2\exception\InvalidResponseTypeException;
use PHPOauth2\exception\InvalidScopeException;
use PHPOauth2\exception\InvalidUserIdException;
use PHPOauth2\exception\InvalidClientIdException;
use PHPOauth2\exception\InvalidRedirectUriException;
use PHPOauth2\exception\InvalidGrantTypeException;
use PHPOauth2\exception\UnexpectedValueException;
use PHPOauth2\response\ResponseToken;
use PHPOauth2\response\ResponseCode;
use PHPOauth2\grant\AuthorizationCode;
use PHPOauth2\grant\ClientCredentials;
use PHPOauth2\grant\Password;
use PHPOauth2\grant\RefreshToken;
use PHPOauth2\grant\OpenId;
use PHPContracts\oauth2\server\factory\AuthCodeFactoryInterface;
use PHPContracts\oauth2\server\factory\AccessTokenFactoryInterface;
use PHPContracts\oauth2\server\factory\RefreshTokenFactoryInterface;
use PHPContracts\oauth2\server\repository\AuthCodeRepositoryInterface;
use PHPContracts\oauth2\server\repository\AccessTokenRepositoryInterface;
use PHPContracts\oauth2\server\repository\RefreshTokenRepositoryInterface;
use PHPContracts\oauth2\server\repository\ClientRepositoryInterface;
use PHPContracts\oauth2\server\repository\UserRepositoryInterface;
use PHPContracts\oauth2\server\entity\RequestEntityInterface;
use PHPContracts\oauth2\server\repository\UserThirdPartyRepositoryInterface;
use PHPContracts\oauth2\server\ResponseTypeInterface;
use PHPContracts\oauth2\server\GrantTypeInterface;
use PHPContracts\oauth2\server\ServerInterface;

class Oauth2Server implements ServerInterface
{
    const RESPONSE_TYPE = [
        ResponseToken::RESPONSE_TYPE => ResponseToken::class,
        ResponseCode::RESPONSE_TYPE  => ResponseCode::class,
    ];

    const GRANT_TYPE = [
        Password::GRANT_TYPE          => Password::class,
        AuthorizationCode::GRANT_TYPE => AuthorizationCode::class,
        ClientCredentials::GRANT_TYPE => ClientCredentials::class,
        RefreshToken::GRANT_TYPE      => RefreshToken::class,
        OpenId::GRANT_TYPE            => OpenId::class
    ];

    public $requestEntity;
    public $clientRepository;
    public $userRepository;
    public $userThirdPartyRepository;
    public $authCodeRepository;
    public $accessTokenRepository;
    public $refreshTokenRepository;
    public $authCodeFactory;
    public $accessTokenFactory;
    public $refreshTokenFactory;
    public $defaultScope;

    public function __construct(
        RequestEntityInterface            $requestEntity            = null,
        UserRepositoryInterface           $userRepository           = null,
        UserThirdPartyRepositoryInterface $userThirdPartyRepository = null,
        ClientRepositoryInterface         $clientRepository         = null,
        AuthCodeRepositoryInterface       $authCodeRepository       = null,
        AuthCodeFactoryInterface          $authCodeFactory          = null,
        AccessTokenRepositoryInterface    $accessTokenRepository    = null,
        AccessTokenFactoryInterface       $accessTokenFactory       = null,
        RefreshTokenRepositoryInterface   $refreshTokenRepository   = null,
        RefreshTokenFactoryInterface      $refreshTokenFactory      = null,
        string $defaultScope = ''
        )
    {
        $this->requestEntity            = $requestEntity;
        $this->userRepository           = $userRepository;
        $this->userThirdPartyRepository = $userThirdPartyRepository;
        $this->clientRepository         = $clientRepository;
        $this->authCodeRepository       = $authCodeRepository;
        $this->accessTokenRepository    = $accessTokenRepository;
        $this->refreshTokenRepository   = $refreshTokenRepository;
        $this->authCodeFactory          = $authCodeFactory;
        $this->accessTokenFactory       = $accessTokenFactory;
        $this->refreshTokenFactory      = $refreshTokenFactory;
        $this->defaultScope             = $defaultScope;
    }

    /**
     * 处理授权请求
     * @param  array $scopeSet
     * @param  int   $userId
     * @return string
     * @throws UnexpectedValueException
     */
    public function handleAuthorizationRequest(array $scopeSet, int $userId):string
    {
        $appId        = $this->requestEntity->getAppId();
        $scope        = $this->requestEntity->getScope();
        $responseType = $this->requestEntity->getResponseType();
        $redirectUri  = $this->requestEntity->getRedirectUri();

        //响应类型非法
        if (!in_array($responseType, self::RESPONSE_TYPE)) {
            throw new InvalidResponseTypeException();
        }
        //作用域非法
        if (!in_array($scope, $scopeSet)) {
            throw new InvalidScopeException();
        }
        /**
         * @var $response ResponseTypeInterface
         */
        $response = new (self::RESPONSE_TYPE[$responseType]);
        $grantType = $response->getGrantType();

        //客户端是否存在
        if (!$clientEntity = $this->clientRepository->getByClientId($appId)) {
            throw new InvalidClientIdException();
        }
        //客户端是否被授予该授权方式
        if (!$clientEntity->validateGrantType($grantType)) {
            throw new InvalidGrantTypeException();
        }
        //客户端授权域是否匹配
        if (!$clientEntity->validateScope($scope)) {
            throw new InvalidScopeException();
        }
        //客户端跳转地址是否匹配
        if (!$clientEntity->validateRedirectUri($redirectUri)) {
            throw new InvalidRedirectUriException();
        }
        //用户是否存在
        if (!$userEntity = $this->userRepository->getByUserId($userId)) {
            throw new InvalidUserIdException();
        }

        /**
         * @var $grant GrantTypeInterface
         */
        $grant = new (self::GRANT_TYPE[$grantType]);

        return $grant->handleAuthorizationRequest($this, $userEntity, $clientEntity);
    }

    /**
     * 处理获取token请求
     * @return array
     * @throws UnexpectedValueException
     */
    public function handleTokenRequest():array
    {
        $grantType = $this->requestEntity->getGrantType();

        //授权类型非法
        if (!in_array($grantType, self::GRANT_TYPE)) {
            throw new InvalidGrantTypeException();
        }
        //客户端是否存在
        if (!$clientEntity = $this->getClientRepository()->getByClientId($this->requestEntity->getAppId())) {
            throw new InvalidClientIdException();
        }
        //客户端是否被授予该授权方式
        if (!$clientEntity->validateGrantType($grantType)) {
            throw new InvalidGrantTypeException();
        }

        /**
         * @var $grant GrantTypeInterface
         */
        $grant = new (self::GRANT_TYPE[$grantType]);

        return $grant->handleTokenRequest($this, $clientEntity);
    }

    /**
     * @return ClientRepositoryInterface
     */
    public function getClientRepository():ClientRepositoryInterface
    {
        return $this->clientRepository;
    }

    /**
     * @return UserRepositoryInterface
     */
    public function getUserRepository():UserRepositoryInterface
    {
        return $this->userRepository;
    }

    /**
     * @return UserThirdPartyRepositoryInterface
     */
    public function getUserThirdPartyRepository(): UserThirdPartyRepositoryInterface
    {
        return $this->userThirdPartyRepository;
    }

    /**
     * @return AuthCodeRepositoryInterface
     */
    public function getAuthCodeRepository(): AuthCodeRepositoryInterface
    {
        return $this->authCodeRepository;
    }

    /**
     * @return AccessTokenRepositoryInterface
     */
    public function getAccessTokenRepository():AccessTokenRepositoryInterface
    {
        return $this->accessTokenRepository;
    }

    /**
     * @return RefreshTokenRepositoryInterface
     */
    public function getRefreshTokenRepository():RefreshTokenRepositoryInterface
    {
        return $this->refreshTokenRepository;
    }

    /**
     * @return AuthCodeFactoryInterface
     */
    public function getAuthCodeFactory():AuthCodeFactoryInterface
    {
        return $this->authCodeFactory;
    }

    /**
     * @return AccessTokenFactoryInterface
     */
    public function getAccessTokenFactory():AccessTokenFactoryInterface
    {
        return $this->accessTokenFactory;
    }

    /**
     * @return RefreshTokenFactoryInterface
     */
    public function getRefreshTokenFactory():RefreshTokenFactoryInterface
    {
        return $this->refreshTokenFactory;
    }

    /**
     * @return RequestEntityInterface
     */
    public function getRequestEntity():RequestEntityInterface
    {
        return $this->requestEntity;
    }

    /**
     * @return string
     */
    public function getDefaultScope():string
    {
        return $this->defaultScope;
    }
}
