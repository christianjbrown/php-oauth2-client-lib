<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

use ChristianBrown\ApiClient\Exception\ExceptionInterface as ApiClientExceptionInterface;

interface RequestExceptionInterface extends ExceptionInterface
{
    public function getRequestException(): ApiClientExceptionInterface;
}
