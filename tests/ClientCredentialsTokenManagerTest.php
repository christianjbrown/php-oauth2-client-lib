<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests;

use ChristianBrown\ApiClient\Exception\ExceptionInterface;
use ChristianBrown\ApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\TtlAwareKeyValueStoreInterface;
use ChristianBrown\OAuth2Client\ClientCredentialsTokenManager;
use ChristianBrown\OAuth2Client\ClientCredentialsTokenManagerInterface;
use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;
use ChristianBrown\OAuth2Client\Model\AccessTokenType;
use ChristianBrown\OAuth2Client\Model\Exception\RequestException;
use ChristianBrown\OAuth2Client\Model\Exception\RequestExceptionInterface;
use ChristianBrown\OAuth2Client\Model\GrantType;
use ChristianBrown\OAuth2Client\TokenManagerInterface;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformerInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function sprintf;
use function time;

#[CoversClass(AccessToken::class)]
#[CoversClass(RequestException::class)]
#[CoversClass(ClientCredentialsTokenManager::class)]
final class ClientCredentialsTokenManagerTest extends TestCase
{
    /**
     * @throws Exception
     */
    #[TestWith([true])]
    #[TestWith([false])]
    #[TestWith([false, 'test-existing-access-token'])]
    #[TestWith([false, 'test-existing-access-token', -42])]
    #[TestWith([false, null, -42])]
    public function testGetAccessTokenFromBasicAuth(bool $forceNew, ?string $existingTokenValue = null, ?int $existingTokenTtl = null): void
    {
        $time = time();
        $headers = [
            TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM,
            TokenManagerInterface::HEADER_KEY_AUTHORIZATION => sprintf(ClientCredentialsTokenManagerInterface::BASIC_AUTH_VALUE_SPRINTF, base64_encode('test-basic-auth-value')),
        ];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::CLIENT_CREDENTIALS->value,
            TokenManagerInterface::REQUEST_KEY_SCOPE => 'test-scope',
            TokenManagerInterface::REQUEST_KEY_CLIENT_ID => 'test-client-id',
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

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::once())
            ->method('transform')
            ->with(['test-new-token-data'])
            ->willReturn($accessToken);

        $accessTokenKeyValueStore = self::createMock(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn($existingTokenValue);
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($existingTokenTtl);
        $accessTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            // @todo Assumes the test can run in the same second.., need to mock time()
            ->with('test-new-access-token', $time + 42);

        $manager = new ClientCredentialsTokenManager($apiRequestSender, $accessTokenKeyValueStore, $tokenTransformer, 'test-url');
        $actual = $manager->getAccessTokenFromBasicAuth('test-basic-auth-value', 'test-scope', 'test-client-id', $forceNew);

        self::assertSame($accessToken, $actual);
    }

    /**
     * @throws Exception
     */
    public function testGetAccessTokenFromBasicAuthExisting(): void
    {
        $time = time();

        $apiRequestSender = self::createMock(JsonApiRequestSenderInterface::class);
        $apiRequestSender->expects(self::never())
            ->method('postForm');

        $tokenTransformer = self::createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $accessTokenKeyValueStore = self::createMock(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-access-token-value'); // Not empty
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($time + 42); // Not expired
        $accessTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $manager = new ClientCredentialsTokenManager($apiRequestSender, $accessTokenKeyValueStore, $tokenTransformer, 'test-url');
        $actual = $manager->getAccessTokenFromBasicAuth('test-basic-auth-value', 'test-scope', 'test-client-id', false);

        self::assertSame(AccessTokenType::BEARER, $actual->getTokenType());
        self::assertNull($actual->getRefreshToken());
        // getTtl() returns an absolute expiry epoch; getExpiresIn() is the
        // relative lifetime remaining, so it is at most the original 42 seconds.
        self::assertGreaterThan(0, $actual->getExpiresIn());
        self::assertLessThanOrEqual(42, $actual->getExpiresIn());
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
    public function testGetAccessTokenFromBasicAuthRequestException(bool $forceNew, ?string $existingTokenValue = null, ?int $existingTokenTtl = null): void
    {
        $headers = [
            TokenManagerInterface::HEADER_KEY_CONTENT_TYPE => TokenManagerInterface::HEADER_VALUE_CONTENT_TYPE_FORM,
            TokenManagerInterface::HEADER_KEY_AUTHORIZATION => sprintf(ClientCredentialsTokenManagerInterface::BASIC_AUTH_VALUE_SPRINTF, base64_encode('test-basic-auth-value')),
        ];
        $bodyData = [
            TokenManagerInterface::REQUEST_KEY_GRANT_TYPE => GrantType::CLIENT_CREDENTIALS->value,
            TokenManagerInterface::REQUEST_KEY_SCOPE => 'test-scope',
            TokenManagerInterface::REQUEST_KEY_CLIENT_ID => 'test-client-id',
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

        $accessTokenKeyValueStore = self::createStub(TtlAwareKeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn($existingTokenValue);
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($existingTokenTtl);

        $manager = new ClientCredentialsTokenManager($apiRequestSender, $accessTokenKeyValueStore, $tokenTransformer, 'test-url');

        $exceptionThrown = false;

        try {
            $manager->getAccessTokenFromBasicAuth('test-basic-auth-value', 'test-scope', 'test-client-id', $forceNew);
        } catch (RequestExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($apiRequestException, $e->getRequestException());
        }
        self::assertTrue($exceptionThrown);
    }
}
