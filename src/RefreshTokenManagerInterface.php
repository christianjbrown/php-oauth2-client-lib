<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestExceptionInterface;

interface RefreshTokenManagerInterface extends TokenManagerInterface
{
    /**
     * @throws RequestExceptionInterface
     * @throws BadResponsePayloadFieldExceptionInterface
     */
    public function getAccessToken(string $clientId, bool $forceNew = false): AccessTokenInterface;
}
