<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client;

use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\Oauth2Client\Model\Token;
use ChristianBrown\Oauth2Client\Model\TokenInterface;

final class RefreshTokenManager extends AbstractTokenManager implements RefreshTokenManagerInterface
{
    private KeyValueStoreInterface $refreshTokenKeyValueStore;

    public function __construct(string $url, string $friendlyName, KeyValueStoreInterface $refreshTokenKeyValueStore, ?KeyValueStoreInterface $accessTokenKeyValueStore = null)
    {
        parent::__construct($url, self::REQUEST_VALUE_GRANT_TYPE_REFRESH_TOKEN, $friendlyName, $accessTokenKeyValueStore);
        $this->refreshTokenKeyValueStore = $refreshTokenKeyValueStore;
    }

    public function getAccessToken(string $clientId, bool $forceNew = false): TokenInterface
    {
        if ($this->accessTokenKeyValueStore instanceof KeyValueStoreInterface) {
            $existingAccessTokenValue = $this->accessTokenKeyValueStore->getValue();
            $existingAccessTokenTtl = $this->accessTokenKeyValueStore->getTtl();
            if (!$forceNew && !empty($existingAccessTokenValue) && $existingAccessTokenTtl) {
                return new Token('access_token', $existingAccessTokenValue, $existingAccessTokenTtl);
            }
        }

        $headers = [self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM];
        $refreshToken = $this->refreshTokenKeyValueStore->getValue();
        $bodyData = [
            self::REQUEST_KEY_GRANT_TYPE => self::REQUEST_VALUE_GRANT_TYPE_REFRESH_TOKEN,
            self::REQUEST_KEY_CLIENT_ID => $clientId,
            self::REQUEST_KEY_REFRESH_TOKEN => $refreshToken,
        ];

        $data = $this->jsonEndpointRequestSender->postData($this->friendlyName, $this->url, [], $headers, $bodyData);

        $token = $this->tokenTransformer->transform($data);

        $this->refreshTokenKeyValueStore->setValue($token->getRefreshToken());
        $this->accessTokenKeyValueStore->setValue($token->getAccessToken(), $token->getExpiresIn());

        return $token;
    }
}
