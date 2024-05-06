<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Transformer;

use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\AccessTokenType;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldException;

use function is_string;

final class AccessTokenTransformer implements AccessTokenTransformerInterface
{
    public function transform(array $data): AccessTokenInterface
    {
        if (empty($data[self::KEY_TOKEN_TYPE]) || !is_string($data[self::KEY_TOKEN_TYPE]) || null === AccessTokenType::tryFrom($data[self::KEY_TOKEN_TYPE])) {
            throw new BadResponsePayloadFieldException(self::KEY_TOKEN_TYPE, $data);
        }
        $tokenType = AccessTokenType::from($data[self::KEY_TOKEN_TYPE]);

        if (empty($data[self::KEY_ACCESS_TOKEN]) || !is_string($data[self::KEY_ACCESS_TOKEN])) {
            throw new BadResponsePayloadFieldException(self::KEY_ACCESS_TOKEN, $data);
        }
        $accessToken = $data[self::KEY_ACCESS_TOKEN];

        if (empty($data[self::KEY_EXPIRES_IN]) || !is_int($data[self::KEY_EXPIRES_IN])) {
            throw new BadResponsePayloadFieldException(self::KEY_EXPIRES_IN, $data);
        }
        $expiresIn = $data[self::KEY_EXPIRES_IN];

        $refreshToken = null;
        if (!empty($data[self::KEY_REFRESH_TOKEN])) {
            if (!is_string($data[self::KEY_REFRESH_TOKEN])) {
                throw new BadResponsePayloadFieldException(self::KEY_REFRESH_TOKEN, $data);
            }
            $refreshToken = $data[self::KEY_REFRESH_TOKEN];
        }

        $scope = null;
        if (!empty($data[self::KEY_SCOPE])) {
            if (!is_string($data[self::KEY_SCOPE])) {
                throw new BadResponsePayloadFieldException(self::KEY_SCOPE, $data);
            }
            $scope = $data[self::KEY_SCOPE];
        }

        return new AccessToken($accessToken, $expiresIn, $refreshToken, $scope, $tokenType);
    }
}
