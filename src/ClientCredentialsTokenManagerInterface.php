<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client;

use ChristianBrown\Oauth2Client\Model\TokenInterface;

interface ClientCredentialsTokenManagerInterface extends TokenManagerInterface
{
    public const BASIC_AUTH_VALUE_SPRINTF = 'Basic %s';

    public function getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId = null, bool $forceNew = false): TokenInterface;
}
