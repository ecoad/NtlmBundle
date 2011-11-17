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

use BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmProtocolToken;

/**
 * NtlmProtocolAuthenticationProvider will verify that the current user has been authenticated
 * in Wordpress
 *
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Authentication\Provider
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 */
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
     * @param ContainerInterface $container so we can get the request
     * @param UserProviderInterface $userProvider
     */
    public function __construct(ContainerInterface $container, UserProviderInterface $userProvider)
    {
        $this->container = $container;
        $this->userProvider = $userProvider;
    }

    public function authenticate(TokenInterface $token)
    {
        $request = $this->container->get('request');
        if ($this->hasNtlmData($request)) {
            $user = $this->container->get('user.entity');
            $user->setUsername($this->getNtlmUsername($request));
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

    protected function hasNtlmData(Request $request) {
        return true;
    }

    protected function getNtlmUsername(Request $request) {
        return $this->container->get('request')->get('ntlm');
    }
}