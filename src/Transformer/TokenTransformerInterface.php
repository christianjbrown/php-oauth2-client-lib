<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client\Transformer;

use ChristianBrown\Oauth2Client\Model\TokenInterface;

interface TokenTransformerInterface
{
    public const KEY_ACCESS_TOKEN = 'access_token';
    public const KEY_EXPIRES_IN = 'expires_in';
    public const KEY_REFRESH_TOKEN = 'refresh_token';
    public const KEY_SCOPE = 'scope';
    public const KEY_TOKEN_TYPE = 'token_type';

    public function transform(array $data): TokenInterface;
}
