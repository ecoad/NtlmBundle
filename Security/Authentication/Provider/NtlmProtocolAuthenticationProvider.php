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
use BrowserCreative\NtlmBundle\Security\User\User;

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
     * @param ContainerInterface $container so we can get the request
     */
    public function __construct(ContainerInterface $container) {
        $this->container = $container;
    }

    public function authenticate(TokenInterface $token)
    {
        $request = $this->container->get('request');
        if ($this->hasNtlmData($request)) {
            $username = $this->getNtlmUser($request);

            try {
                $userProvider = $this->container->get('user.provider');
                $user = $userProvider->loadUserByUsername($username);
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

    protected function getNtlmUser(Request $request) {
        return $this->container->get('request')->get('ntlm');
    }
}