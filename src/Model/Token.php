<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client\Model;

final class Token implements TokenInterface
{
    private string $accessToken;
    private int $expiresIn;
    private ?string $refreshToken;
    private ?string $scope;
    private string $tokenType;

    public function __construct(string $tokenType, string $accessToken, int $expiresIn, ?string $refreshToken = null, ?string $scope = null)
    {
        $this->tokenType = $tokenType;
        $this->accessToken = $accessToken;
        $this->expiresIn = $expiresIn;
        $this->refreshToken = $refreshToken;
        $this->scope = $scope;
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

    public function getTokenType(): string
    {
        return $this->tokenType;
    }
}
