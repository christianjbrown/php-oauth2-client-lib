<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\ApiClient\Exception\ExceptionInterface;
use ChristianBrown\ApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\GrantType;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformerInterface;

final class RefreshTokenManager implements RefreshTokenManagerInterface
{
    private KeyValueStoreInterface $accessTokenKeyValueStore;
    private JsonApiRequestSenderInterface $apiRequestSender;
    private KeyValueStoreInterface $refreshTokenKeyValueStore;
    private AccessTokenTransformerInterface $tokenTransformer;
    private string $url;

    public function __construct(JsonApiRequestSenderInterface $apiRequestSender, KeyValueStoreInterface $accessTokenKeyValueStore, KeyValueStoreInterface $refreshTokenKeyValueStore, AccessTokenTransformerInterface $tokenTransformer, string $url)
    {
        $this->apiRequestSender = $apiRequestSender;
        $this->tokenTransformer = $tokenTransformer;
        $this->url = $url;
        $this->refreshTokenKeyValueStore = $refreshTokenKeyValueStore;
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
    }

    public function getAccessToken(string $clientId, bool $forceNew = false): AccessTokenInterface
    {
        $time = time();

        $existingAccessTokenValue = $this->accessTokenKeyValueStore->getValue();
        $existingAccessTokenTtl = $this->accessTokenKeyValueStore->getTtl();

        if (!$forceNew && !empty($existingAccessTokenValue) && $existingAccessTokenTtl > $time) {
            return new AccessToken($existingAccessTokenValue, $existingAccessTokenTtl);
        }

        $headers = [self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM];
        $refreshTokenValue = $this->refreshTokenKeyValueStore->getValue();
        $bodyData = [
            self::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            self::REQUEST_KEY_CLIENT_ID => $clientId,
            self::REQUEST_KEY_REFRESH_TOKEN => $refreshTokenValue,
        ];

        try {
            $accessTokenData = $this->apiRequestSender->postForm($this->url, [], $headers, $bodyData);
        } catch (ExceptionInterface $e) {
            // @todo Could probably handle 401/403 more specifically
            throw new RequestException($e);
        }

        $accessToken = $this->tokenTransformer->transform($accessTokenData);

        $this->refreshTokenKeyValueStore->setValue($accessToken->getRefreshToken());
        $this->accessTokenKeyValueStore->setValue($accessToken->getAccessToken(), $time + $accessToken->getExpiresIn());

        return $accessToken;
    }
}
