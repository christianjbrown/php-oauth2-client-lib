<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests;

use ChristianBrown\JsonApiClient\JsonApiRequestExceptionInterface;
use ChristianBrown\JsonApiClient\JsonApiRequestSenderInterface;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
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

        $jsonApiRequestSender = $this->createMock(JsonApiRequestSenderInterface::class);
        $jsonApiRequestSender->method('postData')
            ->with('test-url', [], $headers, $bodyData)
            ->willReturn(['test-new-token-data']);

        $accessToken = $this->createMock(AccessTokenInterface::class);
        $accessToken->method('getAccessToken')
            ->willReturn('test-new-access-token');
        $accessToken->method('getExpiresIn')
            ->willReturn(42);

        $tokenTransformer = $this->createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->method('transform')
            ->with(['test-new-token-data'])
            ->willReturn($accessToken);

        $accessTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn($existingTokenValue);
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($existingTokenTtl);

        $accessTokenKeyValueStore->expects(self::once())
            ->method('setValue')
            // @todo Assumes the test can run in the same second.., need to mock time()
            ->with('test-new-access-token', $time + 42);

        $manager = new ClientCredentialsTokenManager($jsonApiRequestSender, $accessTokenKeyValueStore, $tokenTransformer, 'test-url');
        $actual = $manager->getAccessTokenFromBasicAuth('test-basic-auth-value', 'test-scope', 'test-client-id', $forceNew);

        self::assertSame($accessToken, $actual);
    }

    /**
     * @throws Exception
     */
    public function testGetAccessTokenFromBasicAuthExisting(): void
    {
        $time = time();

        $jsonApiRequestSender = $this->createMock(JsonApiRequestSenderInterface::class);
        $jsonApiRequestSender->expects(self::never())
            ->method('postData');

        $tokenTransformer = $this->createMock(AccessTokenTransformerInterface::class);
        $tokenTransformer->expects(self::never())
            ->method('transform');

        $accessTokenKeyValueStore = $this->createMock(KeyValueStoreInterface::class);
        $accessTokenKeyValueStore->method('getValue')
            ->willReturn('test-existing-access-token-value'); // Not empty
        $accessTokenKeyValueStore->method('getTtl')
            ->willReturn($time + 42); // Not expired

        $accessTokenKeyValueStore->expects(self::never())
            ->method('setValue');

        $manager = new ClientCredentialsTokenManager($jsonApiRequestSender, $accessTokenKeyValueStore, $tokenTransformer, 'test-url');
        $actual = $manager->getAccessTokenFromBasicAuth('test-basic-auth-value', 'test-scope', 'test-client-id', false);

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

        $manager = new ClientCredentialsTokenManager($jsonApiRequestSender, $accessTokenKeyValueStore, $tokenTransformer, 'test-url');

        $exceptionThrown = false;

        try {
            $manager->getAccessTokenFromBasicAuth('test-basic-auth-value', 'test-scope', 'test-client-id', $forceNew);
        } catch (RequestExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($jsonApiRequestException, $e->getRequestException());
        }
        self::assertTrue($exceptionThrown);
    }
}
