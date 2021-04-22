<?php
declare(strict_types=1);

namespace Seven\HostnameAuthentication\Security;

use Exception;
use Neos\Cache\Frontend\StringFrontend;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;

class HostnameToken extends AbstractToken implements SessionlessTokenInterface
{
    /**
     * @var StringFrontend
     */
    protected $hostCache;

    /**
     * @param ActionRequest $actionRequest
     * @return bool|void
     * @throws Exception
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $serverParameters = $actionRequest->getHttpRequest()->getServerParams();

        if (isset($serverParameters['HTTP_CF_CONNECTING_IP'])) {
            $ipAddress = $serverParameters['HTTP_CF_CONNECTING_IP'];
        } else {
            $ipAddress = $actionRequest->getHttpRequest()->getAttribute('clientIpAddress');
        }

        $hostCacheIdentifier = sha1($ipAddress);

        if ($this->hostCache->has($hostCacheIdentifier) === false) {
            $this->hostCache->set($hostCacheIdentifier, gethostbyaddr($ipAddress));
        }

        $hostname = $this->hostCache->get($hostCacheIdentifier);

        if (!empty($hostname)) {
            $this->credentials['hostname'] = $hostname;
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return 'Hostname: ' . $this->credentials['hostname'];
    }
}
