<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client\Transformer;

use ChristianBrown\Oauth2Client\Model\Token;
use ChristianBrown\Oauth2Client\Model\TokenInterface;
use ChristianBrown\UserFriendlyException\UserFriendlyException;

use function sprintf;

final class TokenTransformer implements TokenTransformerInterface
{
    private string $friendlyName;

    public function __construct(string $friendlyName)
    {
        $this->friendlyName = $friendlyName;
    }

    public function transform(array $data): TokenInterface
    {
        foreach ([self::KEY_TOKEN_TYPE, self::KEY_ACCESS_TOKEN] as $key) {
            if (empty($data[$key]) || !is_string($data[$key])) {
                throw new UserFriendlyException(sprintf('%s OAuth response missing or corrupted "%s".', $this->friendlyName, $key));
            }
        }
        $tokenType = $data[self::KEY_TOKEN_TYPE];
        $accessToken = $data[self::KEY_ACCESS_TOKEN];

        if (empty($data[self::KEY_EXPIRES_IN]) || !is_int($data[self::KEY_EXPIRES_IN])) {
            throw new UserFriendlyException(sprintf('%s OAuth response missing or corrupted "%s".', $this->friendlyName, self::KEY_EXPIRES_IN));
        }
        $expiresIn = $data[self::KEY_EXPIRES_IN];

        $refreshToken = null;
        if (!empty($data[self::KEY_REFRESH_TOKEN])) {
            if (!is_string($data[self::KEY_REFRESH_TOKEN])) {
                throw new UserFriendlyException(sprintf('%s OAuth response has corrupted "%s".', $this->friendlyName, self::KEY_REFRESH_TOKEN));
            }
            $refreshToken = $data[self::KEY_REFRESH_TOKEN];
        }

        $scope = null;
        if (!empty($data[self::KEY_SCOPE])) {
            if (!is_string($data[self::KEY_SCOPE])) {
                throw new UserFriendlyException(sprintf('%s OAuth response has corrupted "%s".', $this->friendlyName, self::KEY_SCOPE));
            }
            $scope = $data[self::KEY_SCOPE];
        }

        return new Token($tokenType, $accessToken, $expiresIn, $refreshToken, $scope);
    }
}
