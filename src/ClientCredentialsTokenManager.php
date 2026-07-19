<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\ApiClient\Exception\ExceptionInterface;
use ChristianBrown\ApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\Exception\RequestExceptionInterface;
use ChristianBrown\OAuth2Client\Model\GrantType;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformerInterface;

use function array_filter;
use function base64_encode;
use function sprintf;
use function time;

final class ClientCredentialsTokenManager implements ClientCredentialsTokenManagerInterface
{
    private KeyValueStoreInterface $accessTokenKeyValueStore;
    private JsonApiRequestSenderInterface $apiRequestSender;
    private AccessTokenTransformerInterface $tokenTransformer;
    private string $url;

    public function __construct(JsonApiRequestSenderInterface $jsonApiRequestSender, KeyValueStoreInterface $accessTokenKeyValueStore, AccessTokenTransformerInterface $tokenTransformer, string $url)
    {
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
        $this->apiRequestSender = $jsonApiRequestSender;
        $this->tokenTransformer = $tokenTransformer;
        $this->url = $url;
    }

    /**
     * @throws RequestExceptionInterface
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    public function getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId = null, bool $forceNew = false): AccessTokenInterface
    {
        $cachedAccessToken = $this->getCachedAccessToken($forceNew);
        if (null !== $cachedAccessToken) {
            return $cachedAccessToken;
        }

        $time = time();
        $headers = [
            self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM,
            self::HEADER_KEY_AUTHORIZATION => sprintf(self::BASIC_AUTH_VALUE_SPRINTF, base64_encode($basicAuthValue)),
        ];
        $bodyData = array_filter([
            self::REQUEST_KEY_GRANT_TYPE => GrantType::CLIENT_CREDENTIALS->value,
            self::REQUEST_KEY_SCOPE => $scope,
            self::REQUEST_KEY_CLIENT_ID => $clientId,
        ]);

        try {
            $data = $this->apiRequestSender->postForm($this->url, [], $headers, $bodyData);
        } catch (ExceptionInterface $e) {
            // @todo Could probably handle 401/403 more specifically
            throw new RequestException($e);
        }

        $accessToken = $this->tokenTransformer->transform($data);

        $this->accessTokenKeyValueStore->setValue($accessToken->getAccessToken(), $time + $accessToken->getExpiresIn());

        return $accessToken;
    }

    private function getCachedAccessToken(bool $forceNew): ?AccessTokenInterface
    {
        if ($forceNew) {
            return null;
        }

        $value = $this->accessTokenKeyValueStore->getValue();
        if (empty($value)) {
            return null;
        }

        $ttl = $this->accessTokenKeyValueStore->getTtl();
        if (null === $ttl) {
            return null;
        }

        $now = time();
        if ($ttl <= $now) {
            return null;
        }

        // $ttl is the absolute expiry epoch stored at fetch time; AccessToken
        // expects a relative lifetime, so return the seconds still remaining.
        return new AccessToken($value, $ttl - $now);
    }
}
