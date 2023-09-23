<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client;

use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\Oauth2Client\Model\Token;
use ChristianBrown\Oauth2Client\Model\TokenInterface;

use function base64_encode;
use function sprintf;

final class ClientCredentialsTokenManager extends AbstractTokenManager implements ClientCredentialsTokenManagerInterface
{
    public function __construct(string $url, string $friendlyName, ?KeyValueStoreInterface $accessTokenKeyValueStore = null)
    {
        parent::__construct($url, self::REQUEST_VALUE_GRANT_TYPE_CLIENT_CREDENTIALS, $friendlyName, $accessTokenKeyValueStore);
    }

    public function getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId = null, bool $forceNew = false): TokenInterface
    {
        $existingAccessTokenValue = $this->accessTokenKeyValueStore->getValue();
        $existingAccessTokenTtl = $this->accessTokenKeyValueStore->getTtl();

        if (!$forceNew && !empty($existingAccessTokenValue) && $existingAccessTokenTtl) {
            return new Token('access_token', $existingAccessTokenValue, $existingAccessTokenTtl);
        }

        $headers = [
            self::HEADER_KEY_CONTENT_TYPE => self::HEADER_VALUE_CONTENT_TYPE_FORM,
            self::HEADER_KEY_AUTHORIZATION => sprintf(self::BASIC_AUTH_VALUE_SPRINTF, base64_encode($basicAuthValue)),
        ];
        $bodyData = [
            self::REQUEST_KEY_GRANT_TYPE => $this->grantType,
        ];
        if (!empty($scope)) {
            $bodyData[self::REQUEST_KEY_SCOPE] = $scope;
        }
        if (!empty($clientId)) {
            $bodyData[self::REQUEST_KEY_CLIENT_ID] = $clientId;
        }

        $data = $this->jsonEndpointRequestSender->postData($this->friendlyName, $this->url, [], $headers, $bodyData);

        $token = $this->tokenTransformer->transform($data);

        $this->accessTokenKeyValueStore->setValue($token->getAccessToken(), $token->getExpiresIn());

        return $token;
    }
}
