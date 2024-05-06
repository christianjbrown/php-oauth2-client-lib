<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model;

interface TokenInterface
{
    public function getAccessToken(): string;

    public function getExpiresIn(): int;

    public function getRefreshToken(): ?string;

    public function getScope(): ?string;

    public function getTokenType(): TokenType;
}
