<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Transformer;

use ChristianBrown\OAuth2Client\Model\AccessTokenInterface;

interface AccessTokenTransformerInterface
{
    public const KEY_ACCESS_TOKEN = 'access_token';
    public const KEY_EXPIRES_IN = 'expires_in';
    public const KEY_REFRESH_TOKEN = 'refresh_token';
    public const KEY_SCOPE = 'scope';
    public const KEY_TOKEN_TYPE = 'token_type';

    public function transform(array $data): AccessTokenInterface;
}
