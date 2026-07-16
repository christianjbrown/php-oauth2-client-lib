<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests\Model\Exception;

use ChristianBrown\ApiClient\Exception\Request\ConnectException;
use ChristianBrown\ApiClient\Exception\Request\ConnectExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use GuzzleHttp\Exception\ConnectException as GuzzleConnectException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

#[CoversClass(RequestException::class)]
final class RequestExceptionTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function test(): void
    {
        $requestUri = self::createStub(UriInterface::class);
        $requestUri->method('__toString')
            ->willReturn('test-uri');
        $request = self::createStub(RequestInterface::class);
        $request->method('getUri')
            ->willReturn($requestUri);
        $previous = self::createStub(GuzzleConnectException::class);

        $apiClientException = new ConnectException($request, $previous);

        $exception = new RequestException($apiClientException);
        self::assertSame($apiClientException, $exception->getRequestException());
        self::assertSame($apiClientException, $exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertSame(sprintf(ConnectExceptionInterface::MESSAGE, 'test-uri'), $exception->getMessage());
    }
}
