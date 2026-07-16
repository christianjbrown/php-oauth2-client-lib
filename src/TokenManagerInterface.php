<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client;

interface TokenManagerInterface
{
    public const string BASIC_AUTH_VALUE_SPRINTF = 'Basic %s';
    public const string HEADER_KEY_AUTHORIZATION = 'Authorization';
    public const string HEADER_KEY_CONTENT_TYPE = 'Content-Type';
    public const string HEADER_VALUE_CONTENT_TYPE_FORM = 'application/x-www-form-urlencoded';
    public const string REQUEST_KEY_CLIENT_ID = 'client_id';
    public const string REQUEST_KEY_GRANT_TYPE = 'grant_type';
    public const string REQUEST_KEY_REFRESH_TOKEN = 'refresh_token';
    public const string REQUEST_KEY_SCOPE = 'scope';
}
