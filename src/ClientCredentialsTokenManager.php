<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\ApiClient\ApiRequestSenderInterface;
use ChristianBrown\ApiClient\Exception\ExceptionInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\GrantType;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformerInterface;

use function base64_encode;
use function sprintf;

final class ClientCredentialsTokenManager implements ClientCredentialsTokenManagerInterface
{
    private KeyValueStoreInterface $accessTokenKeyValueStore;
    private ApiRequestSenderInterface $apiRequestSender;
    private AccessTokenTransformerInterface $tokenTransformer;
    private string $url;

    public function __construct(ApiRequestSenderInterface $jsonApiRequestSender, KeyValueStoreInterface $accessTokenKeyValueStore, AccessTokenTransformerInterface $tokenTransformer, string $url)
    {
        $this->apiRequestSender = $jsonApiRequestSender;
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
        $this->tokenTransformer = $tokenTransformer;
        $this->url = $url;
    }

    public function getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId = null, bool $forceNew = false): AccessTokenInterface
    {
        $time = time();

        $existingAccessTokenValue = $this->accessTokenKeyValueStore->getValue();
        $existingAccessTokenTtl = $this->accessTokenKeyValueStore->getTtl();

        if (!$forceNew && !empty($existingAccessTokenValue) && $existingAccessTokenTtl > $time) {
            return new AccessToken($existingAccessTokenValue, $existingAccessTokenTtl);
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
            $data = $this->apiRequestSender->postData($this->url, [], $headers, $bodyData);
        } catch (ExceptionInterface $e) {
            // @todo Could probably handle 401/403 more specifically
            throw new RequestException($e);
        }

        $accessToken = $this->tokenTransformer->transform($data);

        $this->accessTokenKeyValueStore->setValue($accessToken->getAccessToken(), $time + $accessToken->getExpiresIn());

        return $accessToken;
    }
}
