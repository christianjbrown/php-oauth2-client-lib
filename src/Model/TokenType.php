<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model;

enum TokenType: string
{
    case ACCESS = 'access_token';
    case REFRESH = 'refresh_token';
}
