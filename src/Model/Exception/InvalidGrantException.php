<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

use ChristianBrown\ApiClient\Exception\ExceptionInterface as ApiClientExceptionInterface;
use RuntimeException;

final class InvalidGrantException extends RuntimeException implements InvalidGrantExceptionInterface
{
    private ApiClientExceptionInterface $requestException;

    public function __construct(ApiClientExceptionInterface $requestException)
    {
        $message = $requestException->getMessage();
        $code = $requestException->getCode();
        parent::__construct($message, $code, $requestException);
        $this->requestException = $requestException;
    }

    public function getRequestException(): ApiClientExceptionInterface
    {
        return $this->requestException;
    }
}
