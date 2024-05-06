<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

use ChristianBrown\JsonApiClient\JsonApiRequestExceptionInterface;

interface RequestExceptionInterface extends ExceptionInterface
{
    public const MESSAGE = 'OAuth request failed';

    public function getRequestException(): JsonApiRequestExceptionInterface;
}
