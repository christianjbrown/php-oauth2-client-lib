<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client\Transformer;

use ChristianBrown\JsonApiClient\BadResponseTransformerInterface;
use Psr\Http\Message\ResponseInterface;

final class BadResponseTransformer implements BadResponseTransformerInterface
{
    private const ERROR_DESCRIPTION_KEY = 'error_description';
    private const MESSAGE_FROM_ERROR_DESCRIPTION = 'Got a %d response from %s: %s';
    private const MESSAGE_GENERIC = 'Got a %d response from %s';
    private string $friendlyName;

    public function __construct(string $friendlyName)
    {
        $this->friendlyName = $friendlyName;
    }

    public function getFriendlyErrorFromBadResponse(ResponseInterface $response): string
    {
        $statusCode = $response->getStatusCode();

        return sprintf(self::MESSAGE_GENERIC, $statusCode, $this->friendlyName);
    }

    public function getFriendlyErrorFromBadResponseJsonData(ResponseInterface $response, array $responseData): string
    {
        $message = $this->getFriendlyErrorFromBadResponse($response);
        if (!empty($responseData[self::ERROR_DESCRIPTION_KEY]) && is_string($responseData[self::ERROR_DESCRIPTION_KEY])) {
            $statusCode = $response->getStatusCode();
            $message = sprintf(self::MESSAGE_FROM_ERROR_DESCRIPTION, $statusCode, $this->friendlyName, $responseData[self::ERROR_DESCRIPTION_KEY]);
        }

        return $message;
    }
}
