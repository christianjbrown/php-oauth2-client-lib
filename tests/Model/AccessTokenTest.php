<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Tests\Model;

use ChristianBrown\OAuth2Client\Model\AccessToken;
use ChristianBrown\OAuth2Client\Model\AccessTokenType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AccessToken::class)]
final class AccessTokenTest extends TestCase
{
    public function test(): void
    {
        $token = new AccessToken('test-access-token', 42, 'test-refresh-token', 'test-scope', AccessTokenType::BEARER);
        self::assertSame('test-access-token', $token->getAccessToken());
        self::assertSame(42, $token->getExpiresIn());
        self::assertSame('test-refresh-token', $token->getRefreshToken());
        self::assertSame('test-scope', $token->getScope());
        self::assertSame(AccessTokenType::BEARER, $token->getTokenType());
    }
}
