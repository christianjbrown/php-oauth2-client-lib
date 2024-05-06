<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

interface BadResponsePayloadFieldExceptionInterface extends ExceptionInterface
{
    public const MESSAGE_SPRINTF = 'OAuth response has corrupted "%s" field.';

    public function getData(): array;

    public function getField(): string;
}
