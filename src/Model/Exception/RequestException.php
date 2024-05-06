<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

use ChristianBrown\JsonApiClient\JsonApiRequestExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

final class RequestException extends RuntimeException implements RequestExceptionInterface
{
    private JsonApiRequestExceptionInterface $requestException;

    public function __construct(JsonApiRequestExceptionInterface $requestException)
    {
        $this->requestException = $requestException;
        $response = $requestException->getResponse();
        $code = 0;
        if ($response instanceof ResponseInterface) {
            $code = $response->getStatusCode();
        }
        parent::__construct(self::MESSAGE, $code, $requestException);
    }

    public function getRequestException(): JsonApiRequestExceptionInterface
    {
        return $this->requestException;
    }
}
