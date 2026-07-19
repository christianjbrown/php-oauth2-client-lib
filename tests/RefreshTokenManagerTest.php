<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests;

use ChristianBrown\ApiClient\Exception\ExceptionInterface;
use ChristianBrown\ApiClient\Exception\Response\ResponseExceptionInterface;
use ChristianBrown\ApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\KeyValueStore\TtlAwareKeyValueStoreInterface;
use ChristianBrown\OAuth2Client\Lock\LockInterface;
use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\AccessTokenType;
use ChristianBrown\OAuth2Client\Model\Exception\InvalidGrantException;
use ChristianBrown\OAuth2Client\Model\Exception\InvalidGrantExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\Exception\RequestExceptionInterface;
use ChristianBrown\OAuth2Client\Model\GrantType;
use ChristianBrown\OAuth2Client\RefreshTokenManager;
use ChristianBrown\OAuth2Client\TokenManagerInterface;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformerInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

use function base64_encode;
use function sprintf;
use function time;

#[CoversClass(AccessToken::class)]
#[CoversClass(RequestException::class)]
#[CoversClass(InvalidGrantException::class)]
#[CoversClass(RefreshTokenManager::class)]
final class RefreshTokenManagerTest extends TestCase
{
    private const string TEST_CLIENT_ID = 'test-client-id';
    private const string TEST_CLIENT_SECRET = 'test-client-secret';

    /**
     * @throws Exception
     */
    #[TestWith([true])]
    #[TestWith([false])]
    #[TestWith([false, 'test-existing-access-token'])]
    #[TestWith([false, 'test-existing-access-token', -42])]
    #[TestWith([false, null, -42])]
    #[TestWith([true, null, null, self::TEST_CLIENT_SECRET])]
    public function testGetAccessToken(bool $forceNew, ?string $existingTokenValue = null, ?int $existingTokenTtl = null, ?string $clientSecret = null): void
    {
        $time = time();
        $headers = [TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            TokenManagerInterface::REQUEST_KEY_REFRESH_TOKEN => 'test-existing-refresh-token-value',
        ];

        if (null !== $clientSecret) {
            $headers[TokenManagerInterface::HEADER_KEY_AUTHORIZATION] = sprintf(TokenManagerInterface::BASIC_AUTH_VALUE_SPRINTF, base64_encode(self::TEST_CLIENT_ID.':'.$clientSecret));
        } else {
            $bodyData[TokenManagerInterface::REQUEST_KEY_CLIENT_ID] = self::TEST_CLIENT_ID;
        }

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::once())
            ->method('postForm')
            ->with('test-url', [], $headers, $bodyData)
            ->willReturn(['test-new-token-data']);

        $accessToken = self::createStub(AccessTokenInterface::class);
        $accessToken->method('getAccessToken')
            ->willReturn('test-new-access-token');
        $accessToken->method('getExpiresIn')
            ->willReturn(42);
        $accessToken->method('getRefreshToken')
            ->willReturn('test-new-refresh-token');

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::once())
            ->method('transform')
            ->with(['test-new-token-data'])
            ->willReturn($accessToken);

        $refreshTokenKeyValueStore = self::createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');
        $refreshTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            ->with('test-new-refresh-token');

        $accessTokenKeyValueStore = self::createMock(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn($existingTokenValue);
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($existingTokenTtl);
        $accessTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            // @todo Assumes the test can run in the same second.., need to mock time()
            ->with('test-new-access-token', $time + 42);

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url', $clientSecret);
        $actual = $manager->getAccessToken(self::TEST_CLIENT_ID, $forceNew);

        self::assertSame($accessToken, $actual);
    }

    /**
     * @throws Exception
     */
    public function testGetAccessTokenExisting(): void
    {
        $time = time();

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::never())
            ->method('postForm');

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $refreshTokenKeyValueStore = self::createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->expects(self::never())
            ->method('getValue');
        $refreshTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $accessTokenKeyValueStore = self::createMock(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-access-token-value'); // Not empty
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($time + 42); // Not expired
        $accessTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url');
        $actual = $manager->getAccessToken(self::TEST_CLIENT_ID, false);

        self::assertSame(AccessTokenType::BEARER, $actual->getTokenType());
        self::assertNull($actual->getRefreshToken());
        // getTtl() returns an absolute expiry epoch; getExpiresIn() is the
        // relative lifetime remaining, so it is at most the original 42 seconds.
        self::assertGreaterThan(0, $actual->getExpiresIn());
        self::assertLessThanOrEqual(42, $actual->getExpiresIn());
        self::assertSame('test-existing-access-token-value', $actual->getAccessToken());
    }

    /**
     * An `invalid_grant` response means the stored refresh token is dead: it is
     * cleared and an InvalidGrantException is thrown so the caller re-authorises.
     *
     * @throws Exception
     */
    public function testGetAccessTokenInvalidGrantClearsRefreshTokenAndThrows(): void
    {
        $apiRequestException = $this->createResponseException('{"error":"invalid_grant"}');

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::once())
            ->method('postForm')
            ->willThrowException($apiRequestException);

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $refreshTokenKeyValueStore = self::createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');
        $refreshTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            ->with(null);

        $accessTokenKeyValueStore = self::createStub(TtlAwareKeyValueStoreInterface::class);

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url');

        $exceptionThrown = false;

        try {
            $manager->getAccessToken(self::TEST_CLIENT_ID);
        } catch (InvalidGrantExceptionInterface $e) {
            $exceptionThrown = true;
            self::assertSame($apiRequestException, $e->getRequestException());
        }
        self::assertTrue($exceptionThrown);
    }

    /**
     * A non-successful response that is not an `invalid_grant` is surfaced as a
     * plain RequestException and must NOT clear the stored refresh token.
     *
     * @throws Exception
     */
    #[TestWith(['not-json'])]
    #[TestWith(['{"foo":"bar"}'])]
    #[TestWith(['{"error":"invalid_client"}'])]
    public function testGetAccessTokenNonInvalidGrantResponseThrowsRequestException(string $responseBody): void
    {
        $apiRequestException = $this->createResponseException($responseBody);

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::once())
            ->method('postForm')
            ->willThrowException($apiRequestException);

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $refreshTokenKeyValueStore = self::createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');
        $refreshTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $accessTokenKeyValueStore = self::createStub(TtlAwareKeyValueStoreInterface::class);

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url');

        $exceptionThrown = false;

        try {
            $manager->getAccessToken(self::TEST_CLIENT_ID);
        } catch (RequestExceptionInterface $e) {
            $exceptionThrown = true;
            self::assertNotInstanceOf(InvalidGrantExceptionInterface::class, $e);
            self::assertSame($apiRequestException, $e->getRequestException());
        }
        self::assertTrue($exceptionThrown);
    }

    /**
     * @throws Exception
     */
    #[TestWith([true])]
    #[TestWith([false])]
    #[TestWith([false, 'test-existing-access-token'])]
    #[TestWith([false, 'test-existing-access-token', -42])]
    #[TestWith([false, null, -42])]
    #[TestWith([true, null, null, self::TEST_CLIENT_SECRET])]
    public function testGetAccessTokenRequestException(bool $forceNew, ?string $existingTokenValue = null, ?int $existingTokenTtl = null, ?string $clientSecret = null): void
    {
        $headers = [TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            TokenManagerInterface::REQUEST_KEY_REFRESH_TOKEN => 'test-existing-refresh-token-value',
        ];

        if (null !== $clientSecret) {
            $headers[TokenManagerInterface::HEADER_KEY_AUTHORIZATION] = sprintf(TokenManagerInterface::BASIC_AUTH_VALUE_SPRINTF, base64_encode(self::TEST_CLIENT_ID.':'.$clientSecret));
        } else {
            $bodyData[TokenManagerInterface::REQUEST_KEY_CLIENT_ID] = self::TEST_CLIENT_ID;
        }

        $apiRequestException = self::createStub(ExceptionInterface::class);

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::once())
            ->method('postForm')
            ->with('test-url', [], $headers, $bodyData)
            ->willThrowException($apiRequestException);

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $refreshTokenKeyValueStore = self::createStub(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');

        $accessTokenKeyValueStore = self::createStub(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn($existingTokenValue);
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($existingTokenTtl);

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url', $clientSecret);

        $exceptionThrown = false;

        try {
            $manager->getAccessToken(self::TEST_CLIENT_ID, $forceNew);
        } catch (RequestExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($apiRequestException, $e->getRequestException());
        }
        self::assertTrue($exceptionThrown);
    }

    /**
     * When a lock is supplied and no cached token exists, the refresh happens
     * under the lock: it is acquired and then released.
     *
     * @throws Exception
     */
    public function testGetAccessTokenWithLockRefreshesUnderLock(): void
    {
        $time = time();
        $headers = [TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            TokenManagerInterface::REQUEST_KEY_REFRESH_TOKEN => 'test-existing-refresh-token-value',
            TokenManagerInterface::REQUEST_KEY_CLIENT_ID => self::TEST_CLIENT_ID,
        ];

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::once())
            ->method('postForm')
            ->with('test-url', [], $headers, $bodyData)
            ->willReturn(['test-new-token-data']);

        $accessToken = self::createStub(AccessTokenInterface::class);
        $accessToken->method('getAccessToken')
            ->willReturn('test-new-access-token');
        $accessToken->method('getExpiresIn')
            ->willReturn(42);
        $accessToken->method('getRefreshToken')
            ->willReturn('test-new-refresh-token');

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::once())
            ->method('transform')
            ->with(['test-new-token-data'])
            ->willReturn($accessToken);

        $refreshTokenKeyValueStore = self::createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');
        $refreshTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            ->with('test-new-refresh-token');

        $accessTokenKeyValueStore = self::createMock(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn(null);
        $accessTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            ->with('test-new-access-token', $time + 42);

        $lock = self::createMock(LockInterface::class);
        $lock->expects(self::once())
            ->method('acquire');
        $lock->expects(self::once())
            ->method('release');

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url', null, $lock);
        $actual = $manager->getAccessToken(self::TEST_CLIENT_ID, false);

        self::assertSame($accessToken, $actual);
    }

    /**
     * The lock is released even when the refresh call fails.
     *
     * @throws Exception
     */
    public function testGetAccessTokenWithLockReleasesOnFailure(): void
    {
        $headers = [TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            TokenManagerInterface::REQUEST_KEY_REFRESH_TOKEN => 'test-existing-refresh-token-value',
            TokenManagerInterface::REQUEST_KEY_CLIENT_ID => self::TEST_CLIENT_ID,
        ];

        $apiRequestException = self::createStub(ExceptionInterface::class);

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::once())
            ->method('postForm')
            ->with('test-url', [], $headers, $bodyData)
            ->willThrowException($apiRequestException);

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $refreshTokenKeyValueStore = self::createStub(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');

        $accessTokenKeyValueStore = self::createStub(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn(null);

        $lock = self::createMock(LockInterface::class);
        $lock->expects(self::once())
            ->method('acquire');
        $lock->expects(self::once())
            ->method('release');

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url', null, $lock);

        $exceptionThrown = false;

        try {
            $manager->getAccessToken(self::TEST_CLIENT_ID, false);
        } catch (RequestExceptionInterface $e) {
            $exceptionThrown = true;
            self::assertSame($apiRequestException, $e->getRequestException());
        }
        self::assertTrue($exceptionThrown);
    }

    /**
     * If another process refreshes the token while we wait for the lock, the
     * re-read after acquiring returns that fresh token and no new call is made.
     *
     * @throws Exception
     */
    public function testGetAccessTokenWithLockReturnsTokenRefreshedWhileWaiting(): void
    {
        $time = time();

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::never())
            ->method('postForm');

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $refreshTokenKeyValueStore = self::createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        // The first read (before the lock) is empty, so we take the lock; the
        // second read (after acquiring it) finds a token another process stored.
        $accessTokenKeyValueStore = self::createMock(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn(null, 'test-refreshed-while-waiting');
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($time + 42);
        $accessTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $lock = self::createMock(LockInterface::class);
        $lock->expects(self::once())
            ->method('acquire');
        $lock->expects(self::once())
            ->method('release');

        $manager = new RefreshTokenManager($apiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url', null, $lock);
        $actual = $manager->getAccessToken(self::TEST_CLIENT_ID, false);

        self::assertSame('test-refreshed-while-waiting', $actual->getAccessToken());
        // getTtl() returns an absolute expiry epoch; getExpiresIn() is the
        // relative lifetime remaining, so it is at most the original 42 seconds.
        self::assertGreaterThan(0, $actual->getExpiresIn());
        self::assertLessThanOrEqual(42, $actual->getExpiresIn());
    }

    /**
     * Build an api-client response exception whose response body is $responseBody.
     *
     * @throws Exception
     */
    private function createResponseException(string $responseBody): ResponseExceptionInterface
    {
        $stream = self::createStub(StreamInterface::class);
        $stream->method('__toString')
            ->willReturn($responseBody);

        $response = self::createStub(ResponseInterface::class);
        $response->method('getBody')
            ->willReturn($stream);

        $responseException = self::createStub(ResponseExceptionInterface::class);
        $responseException->method('getResponse')
            ->willReturn($response);

        return $responseException;
    }
}
