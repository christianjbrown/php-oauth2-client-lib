<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

interface BadResponsePayloadFieldExceptionInterface extends ExceptionInterface
{
    public const string MESSAGE_SPRINTF = "OAuth response has missing, incorrect, or unsupported value in \"%s\" field, data is:\n%s";

    /**
     * @return array<array-key, mixed>
     */
    public function getData(): array;

    public function getField(): string;
}
