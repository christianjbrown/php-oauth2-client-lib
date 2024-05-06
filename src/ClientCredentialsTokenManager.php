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

use function base64_encode;
use function sprintf;

final class ClientCredentialsTokenManager implements ClientCredentialsTokenManagerInterface
{
    private KeyValueStoreInterface $accessTokenKeyValueStore;
    private JsonApiRequestSenderInterface $jsonEndpointRequestSender;
    private TokenTransformerInterface $tokenTransformer;
    private string $url;

    public function __construct(JsonApiRequestSenderInterface $jsonApiRequestSender, KeyValueStoreInterface $accessTokenKeyValueStore, TokenTransformerInterface $tokenTransformer, string $url)
    {
        $this->jsonEndpointRequestSender = $jsonApiRequestSender;
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
        $this->tokenTransformer = $tokenTransformer;
        $this->url = $url;
    }

    public function getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId = null, bool $forceNew = false): TokenInterface
    {
        $time = time();

        $existingAccessTokenValue = $this->accessTokenKeyValueStore->getValue();
        $existingAccessTokenTtl = $this->accessTokenKeyValueStore->getTtl();

        if (!$forceNew && !empty($existingAccessTokenValue) && $existingAccessTokenTtl > $time) {
            return new Token(TokenType::ACCESS, $existingAccessTokenValue, $existingAccessTokenTtl);
        }

        $headers = [
            self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM,
            self::HEADER_KEY_AUTHORIZATION => sprintf(self::BASIC_AUTH_VALUE_SPRINTF, base64_encode($basicAuthValue)),
        ];
        $bodyData = [
            self::REQUEST_KEY_GRANT_TYPE => GrantType::CLIENT_CREDENTIALS->value,
        ];
        if (!empty($scope)) {
            $bodyData[self::REQUEST_KEY_SCOPE] = $scope;
        }
        if (!empty($clientId)) {
            $bodyData[self::REQUEST_KEY_CLIENT_ID] = $clientId;
        }

        try {
            $data = $this->jsonEndpointRequestSender->postData($this->url, [], $headers, $bodyData);
        } catch (JsonApiRequestExceptionInterface $e) {
            // @todo Could probably handle 401/403 more specifically
            throw new RequestException($e);
        }

        $accessToken = $this->tokenTransformer->transform($data);

        $this->accessTokenKeyValueStore->setValue($accessToken->getAccessToken(), $time + $accessToken->getExpiresIn());

        return $accessToken;
    }
}
