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

use function time;

final class RefreshTokenManager implements RefreshTokenManagerInterface
{
    private KeyValueStoreInterface $accessTokenKeyValueStore;
    private JsonApiRequestSenderInterface $apiRequestSender;
    private KeyValueStoreInterface $refreshTokenKeyValueStore;
    private AccessTokenTransformerInterface $tokenTransformer;
    private string $url;

    public function __construct(JsonApiRequestSenderInterface $apiRequestSender, KeyValueStoreInterface $accessTokenKeyValueStore, KeyValueStoreInterface $refreshTokenKeyValueStore, AccessTokenTransformerInterface $tokenTransformer, string $url)
    {
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
        $this->apiRequestSender = $apiRequestSender;
        $this->refreshTokenKeyValueStore = $refreshTokenKeyValueStore;
        $this->tokenTransformer = $tokenTransformer;
        $this->url = $url;
    }

    /**
     * @throws RequestExceptionInterface
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    public function getAccessToken(string $clientId, bool $forceNew = false): AccessTokenInterface
    {
        $cachedAccessToken = $this->getCachedAccessToken($forceNew);
        if (null !== $cachedAccessToken) {
            return $cachedAccessToken;
        }

        $time = time();
        $headers = [self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            self::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            self::REQUEST_KEY_CLIENT_ID => $clientId,
            self::REQUEST_KEY_REFRESH_TOKEN => (string) $this->refreshTokenKeyValueStore->getValue(),
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

        if ($ttl <= time()) {
            return null;
        }

        return new AccessToken($value, $ttl);
    }
}
