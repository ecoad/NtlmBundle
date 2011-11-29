<?php

/**
 * Contains the NtlmProtocolAuthenticationProvider class, part of the Symfony2 Wordpress Bundle
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Authentication\Provider
 */

namespace BrowserCreative\NtlmBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use \Exception;

use BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmProtocolToken;

class NtlmProtocolAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @var UserProviderInterface
     */
    protected $userProvider;

    /**
     * @var array
     */
    protected $trustedRemoteAddresses;

    /**
     * @param ContainerInterface $container so we can get the request
     * @param UserProviderInterface $userProvider
     * @param array $trustedRemoteAddresses
     */
    public function __construct(ContainerInterface $container, UserProviderInterface $userProvider,
        array $trustedRemoteAddresses)
    {
        $this->container = $container;
        $this->userProvider = $userProvider;
        $this->trustedRemoteAddresses = $trustedRemoteAddresses;
    }

    public function authenticate(TokenInterface $token)
    {

        if (!$this->isRemoteAddressAuthorised($_SERVER['REMOTE_ADDR'])) {
            throw new AuthenticationException('NTLM cannot authetnicate against unauthorised IP addresses');
        }

        $username = $this->checkNtlm();

        if ($username) {
            $user = $this->container->get('user.entity');
            $user->setUsername($username);
            $token->setUser($user);

            try {
                /**
                 * Token is passed to loadUserByUsername as we require the credentials for
                 * the LDAP provider. Unfortunately, we cannot use another function, as
                 * ChainUserProvider will fire off the same function which is out of our
                 * control.
                 */
                $user = $this->userProvider->loadUserByUsername($token);
                return new NtlmProtocolToken($user);
            } catch (UsernameNotFoundException $e) {
            }
        }

        throw new AuthenticationException('The NTLM authentication failed');
    }

    public function checkNtlm()
    {
        $ldapRequest = $this->container->get('ntlm.request');


        $username = $ldapRequest->ntlm_prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local", "get_ntlm_user_hash");
        if (!$username) {
            throw new AuthenticationException('The NTLM authentication failed');
        }
        return $username;
    }

    public function isRemoteAddressAuthorised($remoteAddress)
    {
        return in_array($remoteAddress, $this->trustedRemoteAddresses);
    }

    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     *
     * @return Boolean true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof NtlmProtocolToken;
    }
}