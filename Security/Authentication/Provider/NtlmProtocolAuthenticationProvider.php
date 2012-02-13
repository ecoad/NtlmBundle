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
        $logger = $this->container->get('logger');

        
        $logger->info('Trying to authenticate NTLM Protocol provider: ' . $_SERVER['REMOTE_ADDR']);

        if (!$this->isRemoteAddressAuthorised($_SERVER['REMOTE_ADDR'])) {
            $logger->info('Remote address is not authorised for NTLM: ' . $_SERVER['REMOTE_ADDR']);
            throw new AuthenticationException('NTLM cannot authenticate against unauthorised IP addresses');
        }

        if ($this->isLoginFormBeingSubmitted()) {
            $message = 'NTLM cannot be used in conjunction with form submits in login';
            $logger->info($message);
            throw new AuthenticationException($message);
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

                $logger->info('User loaded: ' . $username);

                return new NtlmProtocolToken($user);
            } catch (UsernameNotFoundException $e) {
                $logger->info('Username not found: ' . $username);
            }
        }

        throw new AuthenticationException('The NTLM authentication failed');
    }

    public function checkNtlm()
    {
        $logger = $this->container->get('logger');
        
        $ldapRequest = $this->container->get('ntlm.request');

        $username = $ldapRequest->ntlm_prompt("testwebsite", "workgroup", "ie8tester", "testdomain.local", "mycomputer.local", "get_ntlm_user_hash");
        if (!$username) {
            $logger->info('NTLM auth failed');
            throw new AuthenticationException('The NTLM authentication failed');
        }
        $logger->info('NTLM auth successful: ' . $username);
        return $username;
    }

    public function isRemoteAddressAuthorised($remoteAddress)
    {
        return in_array($remoteAddress, $this->trustedRemoteAddresses);
    }

    public function isLoginFormBeingSubmitted()
    {
        if (($this->container->get('request')->getMethod() == "POST") &&
            (substr($this->container->get('request')->getPathInfo(), 0, 6) == '/login')) {
            
            return true;
        }
        return false;
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