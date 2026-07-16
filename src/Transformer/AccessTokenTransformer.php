<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Transformer;

use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\AccessTokenType;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldException;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;

use function is_int;
use function is_string;

final class AccessTokenTransformer implements AccessTokenTransformerInterface
{
    /**
     * @param array<array-key, mixed> $data
     *
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    public function transform(array $data): AccessTokenInterface
    {
        return new AccessToken(
            $this->extractRequiredString($data, self::KEY_ACCESS_TOKEN),
            $this->extractExpiresIn($data),
            $this->extractOptionalString($data, self::KEY_REFRESH_TOKEN),
            $this->extractOptionalString($data, self::KEY_SCOPE),
            $this->extractTokenType($data),
        );
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    private function extractExpiresIn(array $data): int
    {
        if (empty($data[self::KEY_EXPIRES_IN])) {
            throw new BadResponsePayloadFieldException(self::KEY_EXPIRES_IN, $data);
        }

        if (!is_int($data[self::KEY_EXPIRES_IN])) {
            throw new BadResponsePayloadFieldException(self::KEY_EXPIRES_IN, $data);
        }

        return $data[self::KEY_EXPIRES_IN];
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    private function extractOptionalString(array $data, string $key): ?string
    {
        if (empty($data[$key])) {
            return null;
        }

        if (!is_string($data[$key])) {
            throw new BadResponsePayloadFieldException($key, $data);
        }

        return $data[$key];
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    private function extractRequiredString(array $data, string $key): string
    {
        if (empty($data[$key])) {
            throw new BadResponsePayloadFieldException($key, $data);
        }

        if (!is_string($data[$key])) {
            throw new BadResponsePayloadFieldException($key, $data);
        }

        return $data[$key];
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    private function extractTokenType(array $data): AccessTokenType
    {
        if (empty($data[self::KEY_TOKEN_TYPE])) {
            throw new BadResponsePayloadFieldException(self::KEY_TOKEN_TYPE, $data);
        }

        if (!is_string($data[self::KEY_TOKEN_TYPE])) {
            throw new BadResponsePayloadFieldException(self::KEY_TOKEN_TYPE, $data);
        }

        $tokenType = AccessTokenType::tryFrom($data[self::KEY_TOKEN_TYPE]);
        if (null === $tokenType) {
            throw new BadResponsePayloadFieldException(self::KEY_TOKEN_TYPE, $data);
        }

        return $tokenType;
    }
}
