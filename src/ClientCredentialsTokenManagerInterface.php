<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;

interface ClientCredentialsTokenManagerInterface extends TokenManagerInterface
{
    public const BASIC_AUTH_VALUE_SPRINTF = 'Basic %s';

    public function getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId = null, bool $forceNew = false): AccessTokenInterface;
}
