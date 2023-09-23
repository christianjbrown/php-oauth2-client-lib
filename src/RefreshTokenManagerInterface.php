<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client;

use ChristianBrown\Oauth2Client\Model\TokenInterface;

interface RefreshTokenManagerInterface extends TokenManagerInterface
{
    public const REQUEST_KEY_REFRESH_TOKEN = 'refresh_token';

    public function getAccessToken(string $clientId, bool $forceNew = false): TokenInterface;
}
