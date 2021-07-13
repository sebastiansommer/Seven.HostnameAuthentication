<?php
declare(strict_types=1);

namespace Seven\HostnameAuthentication\Security;

use Exception;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;

class HostnameToken extends AbstractToken implements SessionlessTokenInterface
{
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

        $hostname = gethostbyaddr($ipAddress);

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
