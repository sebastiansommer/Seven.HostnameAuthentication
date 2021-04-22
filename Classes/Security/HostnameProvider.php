<?php
declare(strict_types=1);

namespace Seven\HostnameAuthentication\Security;

use Exception;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;

class HostnameProvider extends AbstractProvider
{
    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @param TokenInterface $authenticationToken
     * @throws Exception
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof HostnameToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.',
                1572424056);
        }

        if (empty($this->options['allowedHosts'])) {
            return;
        }

        if (in_array($authenticationToken->getCredentials()['hostname'], $this->options['allowedHosts'])) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

            $account = new Account();
            $roles = array_map([$this->policyService, 'getRole'], $this->options['authenticateRoles']);
            $account->setRoles($roles);
            $authenticationToken->setAccount($account);
        }
    }

    /**
     * @return array
     */
    public function getTokenClassNames(): array
    {
        return [HostnameToken::class];
    }
}
