<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\JsonApiClient\JsonApiRequestExceptionInterface;
use ChristianBrown\JsonApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\GrantType;
use ChristianBrown\OAuth2Client\Model\Token;
use ChristianBrown\OAuth2Client\Model\TokenInterface;
use ChristianBrown\OAuth2Client\Model\TokenType;
use ChristianBrown\OAuth2Client\Transformer\TokenTransformerInterface;

final class RefreshTokenManager implements RefreshTokenManagerInterface
{
    private KeyValueStoreInterface $accessTokenKeyValueStore;
    private JsonApiRequestSenderInterface $jsonEndpointRequestSender;
    private KeyValueStoreInterface $refreshTokenKeyValueStore;
    private TokenTransformerInterface $tokenTransformer;
    private string $url;

    public function __construct(JsonApiRequestSenderInterface $jsonApiRequestSender, KeyValueStoreInterface $accessTokenKeyValueStore, KeyValueStoreInterface $refreshTokenKeyValueStore, TokenTransformerInterface $tokenTransformer, string $url)
    {
        $this->jsonEndpointRequestSender = $jsonApiRequestSender;
        $this->tokenTransformer = $tokenTransformer;
        $this->url = $url;
        $this->refreshTokenKeyValueStore = $refreshTokenKeyValueStore;
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
    }

    public function getAccessToken(string $clientId, bool $forceNew = false): TokenInterface
    {
        $time = time();

        $existingAccessTokenValue = $this->accessTokenKeyValueStore->getValue();
        $existingAccessTokenTtl = $this->accessTokenKeyValueStore->getTtl();

        if (!$forceNew && !empty($existingAccessTokenValue) && $existingAccessTokenTtl > $time) {
            return new Token(TokenType::ACCESS, $existingAccessTokenValue, $existingAccessTokenTtl);
        }

        $headers = [self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM];
        $refreshTokenValue = $this->refreshTokenKeyValueStore->getValue();
        $bodyData = [
            self::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            self::REQUEST_KEY_CLIENT_ID => $clientId,
            self::REQUEST_KEY_REFRESH_TOKEN => $refreshTokenValue,
        ];

        try {
            $accessTokenData = $this->jsonEndpointRequestSender->postData($this->url, [], $headers, $bodyData);
        } catch (JsonApiRequestExceptionInterface $e) {
            // @todo Could probably handle 401/403 more specifically
            throw new RequestException($e);
        }

        $accessToken = $this->tokenTransformer->transform($accessTokenData);

        $this->refreshTokenKeyValueStore->setValue($accessToken->getRefreshToken());
        $this->accessTokenKeyValueStore->setValue($accessToken->getAccessToken(), $time + $accessToken->getExpiresIn());

        return $accessToken;
    }
}
