# CLAUDE.md

Guidance for working in this repository. Match the existing conventions exactly — this codebase is
small, uniform, and highly opinionated, so new code should be indistinguishable from what's here.

## What this is

A thin, strongly-typed PHP 8.5+ **OAuth 2.0 client**. It fetches access tokens from a token endpoint,
caches them in an interchangeable key-value store, and only re-fetches when the cached token is
missing, expired, or a refresh is forced. Two grant types ship: refresh-token and client-credentials.
It builds on two sibling libraries — `christianjbrown/php-api-client-lib` (the JSON request sender)
and `christianjbrown/php-key-value-store-lib` (the token caches) — and is consumed by other libraries
and a cloud function, so **the public API must not change** (class/interface names, the
`ChristianBrown\OAuth2Client\` namespace, and every public method + constructor signature are frozen).

## Commands

Binaries install into `bin/` (Composer `bin-dir`), not `vendor/bin/`. Both `bin/` and `vendor/` are
gitignored and Composer-installed, so run `composer install` first. The runtime deps and the style
tooling (private `christianjbrown/php-code-quality-scripts` — php-cs-fixer (`@PhpCsFixer`/`@Symfony`)
for formatting + PHP_CodeSniffer 4 with the **`ChristianBrown` coding standard** (slevomat sniffs plus
PSR/PEAR/Squiz/Generic) for linting) are private `dev-main` GitHub packages; installing them needs SSH/`COMPOSER_AUTH`
access to those repos.

| Task | Command |
| --- | --- |
| Run tests + coverage (opens HTML report) | `composer test` |
| Run tests, no coverage | `php -d memory_limit=-1 ./bin/phpunit --no-coverage` |
| Run one test | `php -d memory_limit=-1 ./bin/phpunit --filter RefreshTokenManagerTest` |
| Static analysis (PHPStan level max) | `composer stan` |
| Check code style | `composer check-style` |
| Auto-fix code style | `composer fix-style` |
| Check / fix style on git diff only | `composer check-style-diff` / `composer fix-style-diff` |

Always run `composer fix-style` first (php-cs-fixer auto-fixes what it can), then `composer
check-style` to surface remaining violations that must be fixed by hand, then `composer stan`, then
`composer test` before finishing. If the `composer stan` wrapper runs out of memory, invoke PHPStan
directly: `./bin/phpstan analyse --no-progress --memory-limit=-1`. CI (`.github/workflows/ci.yml`)
runs the same three gates — style → PHPStan → PHPUnit-with-coverage — on push/PR to `main`, supplying
private-repo credentials via the `COMPOSER_AUTH` secret.

## Architecture

Everything lives under the `ChristianBrown\OAuth2Client\` namespace (`src/`), mirrored under
`ChristianBrown\OAuth2Client\Tests\` (`tests/`).

- **`TokenManagerInterface`** — the shared base contract. Carries the request/header constant keys
  (`HEADER_KEY_*`, `HEADER_VALUE_*`, `REQUEST_KEY_*`). Both concrete managers implement a sub-interface
  of it.
- **`RefreshTokenManager` / `RefreshTokenManagerInterface`** — `getAccessToken(string $clientId, bool
  $forceNew = false)`. Constructed with a `JsonApiRequestSenderInterface`, an access-token
  `TtlAwareKeyValueStoreInterface`, a refresh-token `KeyValueStoreInterface`, an
  `AccessTokenTransformerInterface`, and the endpoint `string $url`. The access-token store is typed
  `TtlAwareKeyValueStoreInterface` because the manager reads/writes its expiry (`getTtl()` +
  `setValue($value, $ttl)`); the refresh-token store only holds a value, so it stays the base
  `KeyValueStoreInterface`.
- **`ClientCredentialsTokenManager` / `ClientCredentialsTokenManagerInterface`** —
  `getAccessTokenFromBasicAuth(string $basicAuthValue, ?string $scope = null, ?string $clientId =
  null, bool $forceNew = false)`. Same constructor minus the refresh-token store (its access-token
  store is likewise a `TtlAwareKeyValueStoreInterface`). `BASIC_AUTH_VALUE_SPRINTF` lives on its interface.
- **`Model\AccessToken` / `AccessTokenInterface`** — the immutable token value object
  (`getAccessToken`, `getExpiresIn`, `getRefreshToken`, `getScope`, `getTokenType`).
- **`Model\AccessTokenType`, `Model\GrantType`** — string-backed **enums** (keep them enums). Token
  type is `Bearer`; grant type is `client_credentials` / `refresh_token`.
- **`Transformer\AccessTokenTransformer` / `AccessTokenTransformerInterface`** — validates the decoded
  JSON payload (the `KEY_*` field-name constants live on the interface) and builds an `AccessToken`,
  throwing `BadResponsePayloadFieldException` on any missing/mistyped field.
- **`Model\Exception\`** — the exception hierarchy, rooted at `ExceptionInterface extends Throwable`.
  `RequestException` wraps a failed `php-api-client-lib` request (exposes `getRequestException()`);
  `BadResponsePayloadFieldException` reports a bad payload field (`getField()`, `getData()`). Each
  concrete exception is `final` and implements a matching `...Interface extends ExceptionInterface`.
  There are **no abstract base classes** here (a flat model, like `php-smartthings-api-lib`).

Both managers share the same private `getCachedAccessToken(bool $forceNew): ?AccessTokenInterface`
helper (deliberately duplicated rather than hoisted into a shared base — the estate prefers duplication
over inheritance): it returns the cached token when one is present and unexpired, else `null` so the
caller hits the endpoint.

## Conventions (follow all of these)

- `declare(strict_types=1);` on every file, immediately after `<?php`.
- **Every concrete class is `final` and implements a matching `...Interface`** in the same namespace.
- **Constants live on the interface, not the class**: header/request keys (`TokenManagerInterface`),
  the Basic-auth template (`ClientCredentialsTokenManagerInterface::BASIC_AUTH_VALUE_SPRINTF`), payload
  field names (`AccessTokenTransformerInterface::KEY_*`), and every exception message template
  (`*_SPRINTF`). Message/format text never appears as a literal in a class body — reference the
  interface constant via `self::`.
- **No constructor property promotion** — declare typed `private` properties and assign them in the
  constructor body. Class members are ordered public-before-private (the `ordered_class_elements`
  fixer enforces this; the constructor comes first).
- Import functions with `use function sprintf;` etc. (after class imports, blank line between) and call
  them unqualified.
- Full type declarations on all params/returns; express array shapes via `@param`/`@return`/`@var`
  docblocks (payloads are `array<array-key, mixed>`). Public methods that can throw carry `@throws`
  docblocks naming the concrete exception **interface(s)**, on both the interface and the implementation.
- Dependencies are constructor-injected and typed against interfaces
  (`JsonApiRequestSenderInterface`, `TtlAwareKeyValueStoreInterface` / `KeyValueStoreInterface`,
  `AccessTokenTransformerInterface`) so everything is mockable.
- **A method that does not use `$this` must be `static`** (called via `self::`) — a stateless helper
  is static. Enforced for private methods by the shared `RequireStaticPrivateMethodRule` PHPStan rule
  (via `php-code-quality-scripts`' `config/phpstan.neon`); interface/override methods stay instance.

## Testing

The `phpunit.xml` config is strict (`requireCoverageMetadata`, `beStrictAboutCoverageMetadata`,
`failOnRisky`, `failOnWarning`, `restrictNotices`/`restrictWarnings`, path coverage,
`ignoreIndirectDeprecations`).

- **Keep line, branch, method, class, AND path coverage at 100%** — the suite currently sits at 100%
  on all five metrics. Run `composer test` and check the report (text summary to stdout + HTML at
  `.phpunit.cache/code-coverage-html/index.html`) before finishing.
- **Path coverage and compound conditions: avoid `||`/`&&` inside a single `if`, and avoid `foreach`.**
  xdebug counts a distinct "path" for every combination of branches through a method, and a compound
  boolean condition (e.g. `if (empty($v) || null === $ttl || $ttl <= time())`) spawns branch-combination
  paths that no input can reach, silently capping the method below 100% path coverage. Split guards into
  **one condition per `if`, each with an early return/throw** (see `getCachedAccessToken` and the
  `AccessTokenTransformer::extract*` helpers) so every counted path is reachable and testable. Same
  reasoning for loops — prefer array functions (`array_filter`, e.g. the client-credentials body build)
  over `foreach`, whose back-edge spawns phantom paths. If you genuinely cannot avoid a compound
  condition or loop, call out the resulting sub-100% path coverage rather than chasing phantom paths.
- **Decompose branchy validation into small private helpers.** A method's path count is the product of
  its internal branches; extracting each field check into its own helper (as the transformer does) keeps
  each method's path set small and fully reachable, and keeps the public entry point (`transform`) a
  single linear path.
- **Every test class needs a `#[CoversClass(...)]` attribute** (may list more than one) or the run
  fails. Use PHPUnit 12 **attributes, not annotations**: `#[CoversClass]`, `#[DataProvider]`,
  `#[TestWith]`. The cache-state matrix (`forceNew`, existing value, existing TTL) is driven by
  `#[TestWith]` rows.
- **Double every collaborator, and pick the right kind of double** (PHPUnit 12 emits a notice — and
  the strict config surfaces it — for a `createMock()` that is never given an expectation):
  - **`self::createStub(SomeInterface::class)`** for a *pure return-value double* — one you only feed
    canned answers (`->method(...)->willReturn(...)`/`->willThrowException(...)`) or throw. Do **not**
    call `->with()` on a stub. The `AccessTokenInterface`, the pass-through key-value stores, and the
    wrapped API-client exception are stubbed this way.
  - **`self::createMock(SomeInterface::class)` with `->expects(...)`** for a *verified collaborator* —
    one whose call you assert (`->with(...)`) or whose non-invocation you assert (`->expects(self::never())`).
    The request sender, transformer, and the token-writing key-value stores are mocked this way.
  - Both factories are **static** — `self::createStub(...)` / `self::createMock(...)`.
- Assert statically (`self::assertSame`) and reference the **same interface constants** production code
  uses for headers, body keys, and expected exception messages, so no strings are hardcoded in tests.

## Adding a feature

1. Add the class + its matching `...Interface` in the right namespace, with any constants (keys,
   message templates) on the interface. Concrete classes are `final`.
2. Constructor-inject every collaborator (typed against an interface) so it stays mockable.
3. Keep guards single-condition and extract branchy validation into private helpers, so path coverage
   stays reachable at 100%.
4. Add a matching `#[CoversClass]` test under `tests/`, doubling all collaborators per the rules above.
5. Run `composer fix-style`, then `composer check-style`, then `composer stan`, then `composer test`
   and **confirm the coverage report is 100%** on classes, lines, paths, methods, and branches.
6. Never change an existing public method signature, constructor, class name, or namespace — external
   consumers (including a SmartThings cloud function) depend on them.
