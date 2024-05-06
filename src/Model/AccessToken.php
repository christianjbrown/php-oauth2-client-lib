<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model;

final class AccessToken implements AccessTokenInterface
{
    private string $accessToken;
    private int $expiresIn;
    private ?string $refreshToken;
    private ?string $scope;
    private AccessTokenType $tokenType;

    public function __construct(string $accessToken, int $expiresIn, ?string $refreshToken = null, ?string $scope = null, AccessTokenType $tokenType = AccessTokenType::BEARER)
    {
        $this->accessToken = $accessToken;
        $this->expiresIn = $expiresIn;
        $this->refreshToken = $refreshToken;
        $this->scope = $scope;
        $this->tokenType = $tokenType;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getExpiresIn(): int
    {
        return $this->expiresIn;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function getScope(): ?string
    {
        return $this->scope;
    }

    public function getTokenType(): AccessTokenType
    {
        return $this->tokenType;
    }
}
