<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Model;

enum AccessTokenType: string
{
    case BEARER = 'Bearer';
}
