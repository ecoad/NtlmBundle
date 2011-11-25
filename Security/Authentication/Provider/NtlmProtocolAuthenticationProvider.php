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
        // loune 25/3/2006, updated 22/08/2009
        // For more information see:
        // http://siphon9.net/loune/2007/10/simple-lightweight-ntlm-in-php/

        $headers = apache_request_headers();

        if (!isset($headers['Authorization'])){
            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: NTLM');
            exit;
        }

        $auth = $headers['Authorization'];

        if (substr($auth,0,5) == 'NTLM ') {
            $msg = base64_decode(substr($auth, 5));
            if (substr($msg, 0, 8) != "NTLMSSP\x00")
                die('error header not recognised');

            if ($msg[8] == "\x01") {
                $msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
                    "\x00\x00\x00\x00". // target name len/alloc
                    "\x00\x00\x00\x00". // target name offset
                    "\x01\x02\x81\x00". // flags
                    "\x00\x00\x00\x00\x00\x00\x00\x00". // challenge
                    "\x00\x00\x00\x00\x00\x00\x00\x00". // context
                    "\x00\x00\x00\x00\x00\x00\x00\x00"; // target info len/alloc/offset

                header('HTTP/1.1 401 Unauthorized');
                header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
                exit;
            }
            else if ($msg[8] == "\x03") {
                function get_msg_str($msg, $start, $unicode = true) {
                    $len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
                    $off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
                    if ($unicode)
                        return str_replace("\0", '', substr($msg, $off, $len));
                    else
                        return substr($msg, $off, $len);
                }
                $username = get_msg_str($msg, 36);
                $domain = get_msg_str($msg, 28);
                $workstation = get_msg_str($msg, 44);

                return $username;
            }
        }
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