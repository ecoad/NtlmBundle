<?php

/**
 * Contains the NtlmLogoutHandler class
 *
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Http\Logout
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 */

namespace BrowserCreative\NtlmBundle\Security\Http\Logout;

use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;

/**
 * Handles logging out of SSO-connected apps when the user logs out of Symfony
 *
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Http\Logout
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 */
class NtlmLogoutHandler implements LogoutHandlerInterface
{
    public function logout(Request $request, Response $response, TokenInterface $token)
    {
    }
}