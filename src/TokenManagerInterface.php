<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

interface TokenManagerInterface
{
    public const HEADER_KEY_AUTHORIZATION = 'Authorization';
    public const HEADER_KEY_CONTENT_TYPE = 'Content-Type';
    public const HEADER_VALUE_CONTENT_TYPE_FORM = 'application/x-www-form-urlencoded';
    public const REQUEST_KEY_CLIENT_ID = 'client_id';
    public const REQUEST_KEY_GRANT_TYPE = 'grant_type';
    public const REQUEST_KEY_REFRESH_TOKEN = 'refresh_token';
    public const REQUEST_KEY_SCOPE = 'scope';
}
