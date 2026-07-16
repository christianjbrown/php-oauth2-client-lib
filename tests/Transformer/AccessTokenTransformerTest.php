<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests\Transformer;

use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenType;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldException;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformer;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformerInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(BadResponsePayloadFieldException::class)]
#[CoversClass(AccessToken::class)]
#[CoversClass(AccessTokenTransformer::class)]
final class AccessTokenTransformerTest extends TestCase
{
    private const array GOOD_RESPONSE_PAYLOAD = [
        // Required
        AccessTokenTransformerInterface::KEY_ACCESS_TOKEN => 'test-access-token',
        AccessTokenTransformerInterface::KEY_TOKEN_TYPE => AccessTokenType::BEARER->value,

        // Optional
        AccessTokenTransformerInterface::KEY_EXPIRES_IN => 42,
        AccessTokenTransformerInterface::KEY_SCOPE => 'test-scope',
        AccessTokenTransformerInterface::KEY_REFRESH_TOKEN => 'test-refresh-token',
    ];

    #[TestWith([AccessTokenTransformerInterface::KEY_EXPIRES_IN])]
    public function testTransformFailureNotAInt(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = 'test-string';
        $transformer = new AccessTokenTransformer();

        $exceptionThrown = false;

        try {
            $transformer->transform($data);
        } catch (BadResponsePayloadFieldExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($field, $e->getField());
            self::assertSame($data, $e->getData());
        }
        self::assertTrue($exceptionThrown);
    }

    #[TestWith([AccessTokenTransformerInterface::KEY_ACCESS_TOKEN])]
    #[TestWith([AccessTokenTransformerInterface::KEY_TOKEN_TYPE])]
    #[TestWith([AccessTokenTransformerInterface::KEY_SCOPE])]
    #[TestWith([AccessTokenTransformerInterface::KEY_REFRESH_TOKEN])]
    public function testTransformFailureNotAString(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = 42;
        $transformer = new AccessTokenTransformer();

        $exceptionThrown = false;

        try {
            $transformer->transform($data);
        } catch (BadResponsePayloadFieldExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($field, $e->getField());
            self::assertSame($data, $e->getData());
        }
        self::assertTrue($exceptionThrown);
    }

    #[TestWith([AccessTokenTransformerInterface::KEY_TOKEN_TYPE])]
    public function testTransformFailureNotATokenType(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = 'test-non-matching-string';
        $transformer = new AccessTokenTransformer();

        $exceptionThrown = false;

        try {
            $transformer->transform($data);
        } catch (BadResponsePayloadFieldExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($field, $e->getField());
            self::assertSame($data, $e->getData());
        }
        self::assertTrue($exceptionThrown);
    }

    #[TestWith([AccessTokenTransformerInterface::KEY_ACCESS_TOKEN])]
    #[TestWith([AccessTokenTransformerInterface::KEY_EXPIRES_IN])]
    #[TestWith([AccessTokenTransformerInterface::KEY_TOKEN_TYPE])]
    public function testTransformFailureRequiredEmpty(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = null;
        $transformer = new AccessTokenTransformer();

        $exceptionThrown = false;

        try {
            $transformer->transform($data);
        } catch (BadResponsePayloadFieldExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($field, $e->getField());
            self::assertSame($data, $e->getData());
        }
        self::assertTrue($exceptionThrown);
    }

    #[TestWith([AccessTokenTransformerInterface::KEY_ACCESS_TOKEN])]
    #[TestWith([AccessTokenTransformerInterface::KEY_EXPIRES_IN])]
    #[TestWith([AccessTokenTransformerInterface::KEY_TOKEN_TYPE])]
    public function testTransformFailureRequiredMissing(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        unset($data[$field]);
        $transformer = new AccessTokenTransformer();

        $exceptionThrown = false;

        try {
            $transformer->transform($data);
        } catch (BadResponsePayloadFieldExceptionInterface $e) {
            // We don't want to use expectException*() here because we want to assert the fields passed to it
            $exceptionThrown = true;
            self::assertSame($field, $e->getField());
            self::assertSame($data, $e->getData());
        }
        self::assertTrue($exceptionThrown);
    }

    public function testTransformSuccess(): void
    {
        $transformer = new AccessTokenTransformer();
        $actual = $transformer->transform(self::GOOD_RESPONSE_PAYLOAD);
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[AccessTokenTransformerInterface::KEY_ACCESS_TOKEN], $actual->getAccessToken());
        self::assertSame(AccessTokenType::BEARER, $actual->getTokenType());
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[AccessTokenTransformerInterface::KEY_EXPIRES_IN], $actual->getExpiresIn());
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[AccessTokenTransformerInterface::KEY_SCOPE], $actual->getScope());
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[AccessTokenTransformerInterface::KEY_REFRESH_TOKEN], $actual->getRefreshToken());
    }

    public function testTransformSuccessWithoutOptionalFields(): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        unset($data[AccessTokenTransformerInterface::KEY_SCOPE], $data[AccessTokenTransformerInterface::KEY_REFRESH_TOKEN]);

        $transformer = new AccessTokenTransformer();
        $actual = $transformer->transform($data);
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[AccessTokenTransformerInterface::KEY_ACCESS_TOKEN], $actual->getAccessToken());
        self::assertSame(AccessTokenType::BEARER, $actual->getTokenType());
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[AccessTokenTransformerInterface::KEY_EXPIRES_IN], $actual->getExpiresIn());
        self::assertNull($actual->getScope());
        self::assertNull($actual->getRefreshToken());
    }
}
