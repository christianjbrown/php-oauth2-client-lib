<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

use RuntimeException;
use Throwable;
use function var_export;

final class BadResponsePayloadFieldException extends RuntimeException implements BadResponsePayloadFieldExceptionInterface
{
    private array $data;
    private string $field;

    public function __construct(string $field, array $data, ?Throwable $previous = null)
    {
        $this->field = $field;
        $this->data = $data;

        $message = sprintf(self::MESSAGE_SPRINTF, $field, var_export($data, true));
        parent::__construct($message, 0, $previous);
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function getField(): string
    {
        return $this->field;
    }
}
