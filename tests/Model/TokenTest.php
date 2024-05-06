<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests\Model;

use ChristianBrown\OAuth2Client\Model\Token;
use ChristianBrown\OAuth2Client\Model\TokenType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Token::class)]
final class TokenTest extends TestCase
{
    public function test(): void
    {
        $token = new Token(TokenType::REFRESH, 'test-access-token', 42, 'test-refresh-token', 'test-scope');
        self::assertSame('test-access-token', $token->getAccessToken());
        self::assertSame(42, $token->getExpiresIn());
        self::assertSame('test-refresh-token', $token->getRefreshToken());
        self::assertSame('test-scope', $token->getScope());
        self::assertSame(TokenType::REFRESH, $token->getTokenType());
    }
}
