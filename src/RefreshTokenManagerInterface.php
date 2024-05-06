<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\OAuth2Client\Model\TokenInterface;

interface RefreshTokenManagerInterface extends TokenManagerInterface
{
    public function getAccessToken(string $clientId, bool $forceNew = false): TokenInterface;
}
