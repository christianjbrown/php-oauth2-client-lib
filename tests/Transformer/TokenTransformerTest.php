<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests\Transformer;

use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldException;
use ChristianBrown\OAuth2Client\Model\Exception\BadResponsePayloadFieldExceptionInterface;
use ChristianBrown\OAuth2Client\Model\Token;
use ChristianBrown\OAuth2Client\Model\TokenType;
use ChristianBrown\OAuth2Client\Transformer\TokenTransformer;
use ChristianBrown\OAuth2Client\Transformer\TokenTransformerInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

#[CoversClass(BadResponsePayloadFieldException::class)]
#[CoversClass(Token::class)]
#[CoversClass(TokenTransformer::class)]
final class TokenTransformerTest extends TestCase
{
    private const GOOD_RESPONSE_PAYLOAD = [
        // Required
        TokenTransformerInterface::KEY_ACCESS_TOKEN => 'test-access-token',
        TokenTransformerInterface::KEY_TOKEN_TYPE => TokenType::REFRESH->value,

        // Optional
        TokenTransformerInterface::KEY_EXPIRES_IN => 42,
        TokenTransformerInterface::KEY_SCOPE => 'test-scope',
        TokenTransformerInterface::KEY_REFRESH_TOKEN => 'test-refresh-token',
    ];

    #[TestWith([TokenTransformerInterface::KEY_EXPIRES_IN])]
    public function testTransformFailureNotAInt(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = 'test-string';
        $transformer = new TokenTransformer();

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

    #[TestWith([TokenTransformerInterface::KEY_ACCESS_TOKEN])]
    #[TestWith([TokenTransformerInterface::KEY_TOKEN_TYPE])]
    #[TestWith([TokenTransformerInterface::KEY_SCOPE])]
    #[TestWith([TokenTransformerInterface::KEY_REFRESH_TOKEN])]
    public function testTransformFailureNotAString(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = 42;
        $transformer = new TokenTransformer();

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

    #[TestWith([TokenTransformerInterface::KEY_TOKEN_TYPE])]
    public function testTransformFailureNotATokenType(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = 'test-non-matching-string';
        $transformer = new TokenTransformer();

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

    #[TestWith([TokenTransformerInterface::KEY_ACCESS_TOKEN])]
    #[TestWith([TokenTransformerInterface::KEY_TOKEN_TYPE])]
    public function testTransformFailureRequiredEmpty(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        $data[$field] = null;
        $transformer = new TokenTransformer();

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

    #[TestWith([TokenTransformerInterface::KEY_ACCESS_TOKEN])]
    #[TestWith([TokenTransformerInterface::KEY_TOKEN_TYPE])]
    public function testTransformFailureRequiredMissing(string $field): void
    {
        $data = self::GOOD_RESPONSE_PAYLOAD;
        unset($data[$field]);
        $transformer = new TokenTransformer();

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
        $transformer = new TokenTransformer();
        $actual = $transformer->transform(self::GOOD_RESPONSE_PAYLOAD);
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[TokenTransformerInterface::KEY_ACCESS_TOKEN], $actual->getAccessToken());
        self::assertSame(TokenType::REFRESH, $actual->getTokenType());
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[TokenTransformerInterface::KEY_EXPIRES_IN], $actual->getExpiresIn());
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[TokenTransformerInterface::KEY_SCOPE], $actual->getScope());
        self::assertSame(self::GOOD_RESPONSE_PAYLOAD[TokenTransformerInterface::KEY_REFRESH_TOKEN], $actual->getRefreshToken());
    }
}
