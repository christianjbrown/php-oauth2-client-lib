<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model\Exception;

use RuntimeException;
use Throwable;

use function sprintf;
use function var_export;

final class BadResponsePayloadFieldException extends RuntimeException implements BadResponsePayloadFieldExceptionInterface
{
    /**
     * @var array<array-key, mixed>
     */
    private array $data;
    private string $field;

    /**
     * @param string                  $field    The name of the offending payload field
     * @param array<array-key, mixed> $data     The full response payload
     * @param null|Throwable          $previous The previous throwable
     */
    public function __construct(string $field, array $data, ?Throwable $previous = null)
    {
        $this->field = $field;
        $this->data = $data;

        $message = sprintf(self::MESSAGE_SPRINTF, $field, var_export($data, true));
        parent::__construct($message, 0, $previous);
    }

    /**
     * @return array<array-key, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    public function getField(): string
    {
        return $this->field;
    }
}
