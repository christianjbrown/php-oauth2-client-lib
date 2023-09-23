<?php

declare(strict_types=1);

namespace ChristianBrown\Oauth2Client;

use ChristianBrown\JsonApiClient\RequestSender;
use ChristianBrown\KeyValueStore\KeyValueStoreInterface;
use ChristianBrown\KeyValueStore\MemoryKeyValueStore;
use ChristianBrown\Oauth2Client\Transformer\BadResponseTransformer;
use ChristianBrown\Oauth2Client\Transformer\TokenTransformer;
use RuntimeException;

use function in_array;
use function sprintf;

abstract class AbstractTokenManager implements TokenManagerInterface
{
    protected ?KeyValueStoreInterface $accessTokenKeyValueStore;
    protected string $friendlyName;
    protected string $grantType;
    protected RequestSender $jsonEndpointRequestSender;
    protected TokenTransformer $tokenTransformer;
    protected string $url;

    public function __construct(string $url, string $grantType, string $friendlyName, ?KeyValueStoreInterface $accessTokenKeyValueStore = null)
    {
        $this->accessTokenKeyValueStore = $accessTokenKeyValueStore;
        if (null === $accessTokenKeyValueStore) {
            $this->accessTokenKeyValueStore = new MemoryKeyValueStore();
        }
        $this->url = $url;
        $this->friendlyName = $friendlyName;
        $this->grantType = $grantType;

        if (!in_array($this->grantType, self::REQUEST_VALUE_GRANT_TYPES, true)) {
            throw new RuntimeException(sprintf('Grant type %s not supported', $grantType));
        }

        $jsonEndpointBadResponseParser = new BadResponseTransformer($friendlyName);
        $this->jsonEndpointRequestSender = new RequestSender($jsonEndpointBadResponseParser);
        $this->tokenTransformer = new TokenTransformer($friendlyName);
    }
}
