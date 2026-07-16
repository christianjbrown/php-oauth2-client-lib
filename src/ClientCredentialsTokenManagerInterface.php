<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestExceptionInterface;

interface ClientCredentialsTokenManagerInterface extends TokenManagerInterface
{
    public const string BASIC_AUTH_VALUE_SPRINTF = 'Basic %s';

    /**
     * @throws RequestExceptionInterface
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    public function getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId = null, bool $forceNew = false): AccessTokenInterface;
}
