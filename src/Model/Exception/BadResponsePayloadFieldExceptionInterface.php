<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

interface BadResponsePayloadFieldExceptionInterface extends ExceptionInterface
{
    public const MESSAGE_SPRINTF = "OAuth response has wrong value type or missing \"%s\" field, data is:\n%s";

    public function getData(): array;

    public function getField(): string;
}
