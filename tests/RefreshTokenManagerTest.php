<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests;

use ChristianBrown\JsonApiClient\JsonApiRequestExceptionInterface;
use ChristianBrown\JsonApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\AccessTokenType;
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

use function time;

#[CoversClass(AccessToken::class)]
#[CoversClass(RequestException::class)]
#[CoversClass(RefreshTokenManager::class)]
final class RefreshTokenManagerTest extends TestCase
{
    /**
     * @throws Exception
     */
    #[TestWith([true])]
    #[TestWith([false])]
    #[TestWith([false, 'test-existing-access-token'])]
    #[TestWith([false, 'test-existing-access-token', -42])]
    #[TestWith([false, null, -42])]
    public function testGetAccessToken(bool $forceNew, ?string $existingTokenValue = null, ?int $existingTokenTtl = null): void
    {
        $time = time();
        $headers = [TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            TokenManagerInterface::REQUEST_KEY_CLIENT_ID => 'test-client-id',
            TokenManagerInterface::REQUEST_KEY_REFRESH_TOKEN => 'test-existing-refresh-token-value',
        ];

        $jsonApiRequestSender = $this->createMock(JsonApiRequestSenderInterface::class);
        $jsonApiRequestSender->method('postData')
            ->with('test-url', [], $headers, $bodyData)
            ->willReturn(['test-new-token-data']);

        $accessToken = $this->createMock(AccessTokenInterface::class);
        $accessToken->method('getAccessToken')
            ->willReturn('test-new-access-token');
        $accessToken->method('getExpiresIn')
            ->willReturn(42);
        $accessToken->method('getRefreshToken')
            ->willReturn('test-new-refresh-token');

        $tokenTransformer = $this->createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->method('transform')
            ->with(['test-new-token-data'])
            ->willReturn($accessToken);

        $refreshTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');
        $refreshTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            ->with('test-new-refresh-token');

        $accessTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn($existingTokenValue);
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($existingTokenTtl);

        $accessTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            // @todo Assumes the test can run in the same second.., need to mock time()
            ->with('test-new-access-token', $time + 42);

        $manager = new RefreshTokenManager($jsonApiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url');
        $actual = $manager->getAccessToken('test-client-id', $forceNew);

        self::assertSame($accessToken, $actual);
    }

    /**
     * @throws Exception
     */
    public function testGetAccessTokenExisting(): void
    {
        $time = time();

        $jsonApiRequestSender = $this->createMock(JsonApiRequestSenderInterface::class);
        $jsonApiRequestSender->expects(self::never())
            ->method('postData');

        $tokenTransformer = $this->createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $refreshTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->expects(self::never())
            ->method('getValue');
        $refreshTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $accessTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-access-token-value'); // Not empty
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($time + 42); // Not expired

        $accessTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $manager = new RefreshTokenManager($jsonApiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url');
        $actual = $manager->getAccessToken('test-client-id', false);

        self::assertSame(AccessTokenType::BEARER, $actual->getTokenType());
        self::assertNull($actual->getRefreshToken());
        // @todo Assumes the test can run within 42 seconds, ideally need to mock time()
        self::assertSame($actual->getExpiresIn(), $time + 42);
        self::assertSame('test-existing-access-token-value', $actual->getAccessToken());
    }

    /**
     * @throws Exception
     */
    #[TestWith([true])]
    #[TestWith([false])]
    #[TestWith([false, 'test-existing-access-token'])]
    #[TestWith([false, 'test-existing-access-token', -42])]
    #[TestWith([false, null, -42])]
    public function testGetAccessTokenRequestException(bool $forceNew, ?string $existingTokenValue = null, ?int $existingTokenTtl = null): void
    {
        $headers = [TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::REFRESH_TOKEN->value,
            TokenManagerInterface::REQUEST_KEY_CLIENT_ID => 'test-client-id',
            TokenManagerInterface::REQUEST_KEY_REFRESH_TOKEN => 'test-existing-refresh-token-value',
        ];

        $jsonApiRequestException = $this->createMock(JsonApiRequestExceptionInterface::class);

        $jsonApiRequestSender = $this->createMock(JsonApiRequestSenderInterface::class);
        $jsonApiRequestSender->method('postData')
            ->with('test-url', [], $headers, $bodyData)
            ->willThrowException($jsonApiRequestException);

        $tokenTransformer = $this->createMock(AccessTokenTransformerInterface::class);

        $refreshTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $refreshTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-refresh-token-value');

        $accessTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn($existingTokenValue);
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($existingTokenTtl);

        $manager = new RefreshTokenManager($jsonApiRequestSender, $accessTokenKeyValueStore, $refreshTokenKeyValueStore, $tokenTransformer, 'test-url');

        $exceptionThrown = false;

        try {
            $manager->getAccessToken('test-client-id', $forceNew);
        } catch (RequestExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($jsonApiRequestException, $e->getRequestException());
        }
        self::assertTrue($exceptionThrown);
    }
}
