<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests\Model\Exception;

use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldException;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(BadResponsePayloadFieldException::class)]
final class BadResponsePayloadFieldExceptionTest extends TestCase
{
    public function test(): void
    {
        $exception = new BadResponsePayloadFieldException('test-field', ['test-data']);
        self::assertSame('test-field', $exception->getField());
        self::assertSame(['test-data'], $exception->getData());
        self::assertSame(sprintf(BadResponsePayloadFieldExceptionInterface::MESSAGE_SPRINTF, 'test-field', var_export(['test-data'], true)), $exception->getMessage());
    }
}
