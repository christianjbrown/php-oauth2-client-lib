<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\ApiClient\Exception\ExceptionInterface;
use ChristianBrown\ApiClient\Exception\Response\ResponseExceptionInterface;
use ChristianBrown\ApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\KeyValueStore\TtlAwareKeyValueStoreInterface;
use ChristianBrown\OAuth2Client\Lock\LockInterface;
use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\InvalidGrantException;
use ChristianBrown\OAuth2Client\Model\Exception\InvalidGrantExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\Exception\RequestExceptionInterface;
use ChristianBrown\OAuth2Client\Model\GrantType;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformerInterface;
use Throwable;

use function base64_encode;
use function is_array;
use function json_decode;
use function sprintf;
use function time;

final class RefreshTokenManager implements RefreshTokenManagerInterface
{
    private TtlAwareKeyValueStoreInterface $accessTokenKeyValueStore;
    private JsonApiRequestSenderInterface $apiRequestSender;
    private ?string $clientSecret;
    private ?LockInterface $lock;
    private KeyValueStoreInterface $refreshTokenKeyValueStore;
    private AccessTokenTransformerInterface $tokenTransformer;
    private string $url;

    public function __construct(JsonApiRequestSenderInterface $apiRequestSender, TtlAwareKeyValueStoreInterface $accessTokenKeyValueStore, KeyValueStoreInterface $refreshTokenKeyValueStore, AccessTokenTransformerInterface $tokenTransformer, string $url, ?string $clientSecret = null, ?LockInterface $lock = null)
    {
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
        $this->apiRequestSender = $apiRequestSender;
        $this->clientSecret = $clientSecret;
        $this->lock = $lock;
        $this->refreshTokenKeyValueStore = $refreshTokenKeyValueStore;
        $this->tokenTransformer = $tokenTransformer;
        $this->url = $url;
    }

    /**
     * @throws RequestExceptionInterface
     * @throws InvalidGrantExceptionInterface
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    public function getAccessToken(string $clientId, bool $forceNew = false): AccessTokenInterface
    {
        $cachedAccessToken = $this->getCachedAccessToken($forceNew);
        if (null !== $cachedAccessToken) {
            return $cachedAccessToken;
        }

        // Without a lock, refresh directly (the historical behaviour).
        if (null === $this->lock) {
            return $this->fetchAndStoreAccessToken($clientId);
        }

        // With a lock, serialise the refresh so a rotating refresh token is not
        // spent by two concurrent refreshes. Release explicitly on both the
        // success and failure paths (rather than a `finally`, whose implicit
        // exception edge leaves an unreachable path) so the lock is always freed.
        $this->lock->acquire();

        try {
            $accessToken = $this->getCachedOrFetchedAccessToken($clientId, $forceNew);
        } catch (Throwable $exception) {
            $this->lock->release();

            throw $exception;
        }

        $this->lock->release();

        return $accessToken;
    }

    /**
     * @throws RequestExceptionInterface
     * @throws InvalidGrantExceptionInterface
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    private function fetchAndStoreAccessToken(string $clientId): AccessTokenInterface
    {
        $time = time();
        $headers = [self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            self::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            self::REQUEST_KEY_REFRESH_TOKEN => (string) $this->refreshTokenKeyValueStore->getValue(),
        ];

        if (null !== $this->clientSecret) {
            $headers[self::HEADER_KEY_AUTHORIZATION] = sprintf(self::BASIC_AUTH_VALUE_SPRINTF, base64_encode($clientId.':'.$this->clientSecret));
        } else {
            $bodyData[self::REQUEST_KEY_CLIENT_ID] = $clientId;
        }

        try {
            $accessTokenData = $this->apiRequestSender->postForm($this->url, [], $headers, $bodyData);
        } catch (ExceptionInterface $e) {
            if ($this->isInvalidGrant($e)) {
                // The refresh token is dead (revoked/expired): drop it so it is
                // not retried forever, and signal that a fresh authorisation is
                // required rather than a transient request failure.
                $this->refreshTokenKeyValueStore->setValue(null);

                throw new InvalidGrantException($e);
            }

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

        $now = time();
        if ($ttl <= $now) {
            return null;
        }

        // $ttl is the absolute expiry epoch stored at fetch time; AccessToken
        // expects a relative lifetime, so return the seconds still remaining.
        return new AccessToken($value, $ttl - $now);
    }

    /**
     * Re-read the cache and, only if it is still empty, refresh. Called under
     * the lock: another process may have refreshed while we waited for it, in
     * which case its freshly stored token is returned without a new call.
     *
     * @throws RequestExceptionInterface
     * @throws InvalidGrantExceptionInterface
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    private function getCachedOrFetchedAccessToken(string $clientId, bool $forceNew): AccessTokenInterface
    {
        $cachedAccessToken = $this->getCachedAccessToken($forceNew);
        if (null !== $cachedAccessToken) {
            return $cachedAccessToken;
        }

        return $this->fetchAndStoreAccessToken($clientId);
    }

    private function isInvalidGrant(ExceptionInterface $e): bool
    {
        if (!$e instanceof ResponseExceptionInterface) {
            return false;
        }

        $decoded = json_decode((string) $e->getResponse()->getBody(), true);
        if (!is_array($decoded)) {
            return false;
        }

        if (!isset($decoded[self::RESPONSE_KEY_ERROR])) {
            return false;
        }

        return self::ERROR_INVALID_GRANT === $decoded[self::RESPONSE_KEY_ERROR];
    }
}
