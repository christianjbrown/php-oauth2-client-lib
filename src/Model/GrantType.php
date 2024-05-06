<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model;

enum GrantType: string
{
    case CLIENT_CREDENTIALS = 'client_credentials';
    case REFRESH_TOKEN = 'refresh_token';
}
