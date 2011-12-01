<?php

/**
 * Contains the NtlmFormLoginAuthenticationProvider class, part of the Symfony2 Wordpress Bundle
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Authentication\Provider
 */

namespace BrowserCreative\NtlmBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use BrowserCreative\NtlmBundle\Security\User\User;
use BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmProtocolUsernamePasswordToken;

/**
 * NtlmFormLoginAuthenticationProvider will authenticate the user with Wordpress
 *
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Authentication\Provider
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 */
class NtlmFormLoginAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     *
     * @var string
     */
    protected $rememberMeParameter;

    /**
     *
     * @var ContainerInterface
     */
    protected $container;

    /**
     * Constructor
     *
     * @param string $rememberMeParameter the name of the request parameter to use to determine
     *                                    whether to remember the user
     * @param ContainerInterface $container so we can get the request and check the remember-me param
     * @param UserProviderInterface $userProvider
     */
    public function __construct($rememberMeParameter = '_remember_me', ContainerInterface $container = null,
        UserProviderInterface $userProvider)
    {
        $this->rememberMeParameter = $rememberMeParameter;
        $this->container = $container;
        $this->userProvider = $userProvider;
    }

    public function authenticate(TokenInterface $token)
    {
        $user = $this->container->get('user.entity');
        $user->setUsername($token->getUsername());
        $user->setPassword($token->getCredentials());
        $ntlmToken = new NtlmProtocolUsernamePasswordToken($user, $token->getCredentials(), $token->getProviderKey());

        try {
            $user = $this->userProvider->loadUserByUsername($ntlmToken);
            $this->checkAuthentication($user, $ntlmToken);

            return new NtlmProtocolUsernamePasswordToken($user, $ntlmToken->getCredentials(),
                $ntlmToken->getProviderKey(), $user->getRoles());

        } catch (UsernameNotFoundException $e) {
            throw new BadCredentialsException('The supplied credentials are incorrect');
        }

        throw new AuthenticationException('Unable to authenticate');
    }

    protected function checkAuthentication(UserInterface $user, NtlmProtocolUsernamePasswordToken $token)
    {
        $invalidPasswordMessage = 'The presented password is invalid.';
        $noPasswordMessage = 'The presented password cannot be empty.';

        $currentUser = $token->getUser();
        if ($currentUser instanceof UserInterface) {
            if ($currentUser->getPassword() !== $user->getDecryptedPassword($this->container->getParameter('secret'))) {
                throw new BadCredentialsException($invalidPasswordMessage);
            }
        } else {
            if (!$presentedPassword = $token->getCredentials()) {
                throw new BadCredentialsException($noPasswordMessage);
            }

            if ($user->getDecryptedPassword($this->container->getParameter('secret')) !== $presentedPassword) {
                throw new BadCredentialsException($invalidPasswordMessage);
            }
        }
    }

    /**
     * Checks whether the user requested to be remembered
     *
     * @return boolean
     */
    protected function isRememberMeRequested()
    {
        if (!($this->container && $request = $this->container->get('request'))) {
            return false;
        }

        $remember = $request->request->get($this->rememberMeParameter, null, true);

        return $remember === 'true' || $remember === 'on' || $remember === '1' || $remember === 'yes';
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken;
    }
}