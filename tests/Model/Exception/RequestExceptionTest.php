<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests\Model\Exception;

use ChristianBrown\JsonApiClient\JsonApiRequestExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\Exception\RequestExceptionInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

#[CoversClass(RequestException::class)]
final class RequestExceptionTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function test(): void
    {
        $requestException = $this->createMock(JsonApiRequestExceptionInterface::class);
        $exception = new RequestException($requestException);
        self::assertSame($requestException, $exception->getRequestException());
        self::assertSame($requestException, $exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertSame(RequestExceptionInterface::MESSAGE, $exception->getMessage());
    }

    /**
     * @throws Exception
     */
    public function testWithResponse(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')
            ->willReturn(42);

        $requestException = $this->createMock(JsonApiRequestExceptionInterface::class);
        $requestException->method('getResponse')
            ->willReturn($response);
        $exception = new RequestException($requestException);
        self::assertSame($requestException, $exception->getRequestException());
        self::assertSame($requestException, $exception->getPrevious());
        self::assertSame(42, $exception->getCode());
        self::assertSame(RequestExceptionInterface::MESSAGE, $exception->getMessage());
    }
}
