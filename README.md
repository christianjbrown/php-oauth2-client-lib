# OAuth2 Client

[![CI](https://github.com/christianjbrown/php-oauth2-client-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/christianjbrown/php-oauth2-client-lib/actions/workflows/ci.yml)

A small, strongly-typed PHP **OAuth 2.0 client** that fetches and caches access tokens. It hides
the token endpoint behind a couple of token managers, caches the resulting access (and refresh) token
in an interchangeable [key-value store](https://github.com/christianjbrown/php-key-value-store-lib),
and only calls the endpoint again when the cached token is missing, expired, or a refresh is forced.

Two grant types ship today:

- **Refresh token** (`RefreshTokenManager`) — exchanges a stored refresh token for a new access token.
- **Client credentials** (`ClientCredentialsTokenManager`) — exchanges HTTP Basic credentials for an
  access token.

Both return an `AccessTokenInterface` and normalise transport and payload failures into a single
library exception hierarchy, so callers stay decoupled from the underlying HTTP client.



## :heavy_check_mark: Prerequisites

- [Git](https://git-scm.com/)
- [PHP](https://www.php.net/) 8.5 or higher (8.x)
- [Composer](https://getcomposer.org/)

:bulb: If you're on MacOS and have [Homebrew](https://brew.sh/), PHP and Composer will install with `brew install composer`.



## :building_construction: Installation

For your composer-enabled project:

```bash
composer require christianjbrown/php-oauth2-client-lib
```



## :computer: Usage

Both managers are constructed with a JSON API request sender (from
[`php-api-client-lib`](https://github.com/christianjbrown/php-api-client-lib)), one or more key-value
stores for the cached tokens, an access-token transformer, and the token endpoint URL.



### :arrows_counterclockwise: Refresh token grant

```php
use ChristianBrown\OAuth2Client\RefreshTokenManager;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformer;

$manager = new RefreshTokenManager(
    $jsonApiRequestSender, // ChristianBrown\ApiClient\JsonApiRequestSenderInterface
    $accessTokenStore,     // ChristianBrown\KeyValueStore\KeyValueStoreInterface
    $refreshTokenStore,    // ChristianBrown\KeyValueStore\KeyValueStoreInterface
    new AccessTokenTransformer(),
    'https://example.com/oauth/token',
);

$accessToken = $manager->getAccessToken('my-client-id');

$accessToken->getAccessToken(); // the bearer token string
$accessToken->getExpiresIn();   // seconds until expiry

// Force a refresh even if a valid token is cached:
$accessToken = $manager->getAccessToken('my-client-id', true);
```

The manager returns the cached access token while it is still valid. Otherwise it POSTs the stored
refresh token to the endpoint, caches the new access and refresh tokens, and returns the fresh token.



### :key: Client credentials grant

```php
use ChristianBrown\OAuth2Client\ClientCredentialsTokenManager;
use ChristianBrown\OAuth2Client\Transformer\AccessTokenTransformer;

$manager = new ClientCredentialsTokenManager(
    $jsonApiRequestSender, // ChristianBrown\ApiClient\JsonApiRequestSenderInterface
    $accessTokenStore,     // ChristianBrown\KeyValueStore\KeyValueStoreInterface
    new AccessTokenTransformer(),
    'https://example.com/oauth/token',
);

// The Basic auth value is the raw "client_id:client_secret"; the manager base64-encodes it.
$accessToken = $manager->getAccessTokenFromBasicAuth(
    'my-client-id:my-client-secret',
    'my-scope',   // optional
    'my-client-id', // optional
);

$accessToken->getAccessToken();
```



### :ticket: The access token

Every manager returns a `ChristianBrown\OAuth2Client\Model\AccessTokenInterface`:

```php
public function getAccessToken(): string;
public function getExpiresIn(): int;
public function getRefreshToken(): ?string;
public function getScope(): ?string;
public function getTokenType(): AccessTokenType; // enum, currently AccessTokenType::BEARER
```



## :rotating_light: Error handling

Everything the library throws implements
`ChristianBrown\OAuth2Client\Model\Exception\ExceptionInterface` (which extends `Throwable`):

- **`RequestExceptionInterface`** — the token endpoint request failed. The original
  `php-api-client-lib` exception is available via `getRequestException()`.
- **`BadResponsePayloadFieldExceptionInterface`** — the endpoint responded, but a field was missing,
  the wrong type, or an unsupported value. `getField()` and `getData()` expose the offending field and
  the full payload.

```php
use ChristianBrown\OAuth2Client\Model\Exception\ExceptionInterface;

try {
    $accessToken = $manager->getAccessToken('my-client-id');
} catch (ExceptionInterface $e) {
    print $e->getMessage();
}
```



## :page_facing_up: License

Released under the [MIT License](LICENSE).
