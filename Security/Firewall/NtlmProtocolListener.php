<?php

/**
 * Contains the NtlmProtocolListener class
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Firewall
 */

namespace BrowserCreative\NtlmBundle\Security\Firewall;

use BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmProtocolToken;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * NtlmProtocolListener checks whether the user has been authenticated against the NTLM protocol
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Firewall
 */
class NtlmProtocolListener implements ListenerInterface
{
    
    /**
     *
     * @var SecurityContextInterface
     */
    protected $securityContext;
    
    /**
     *
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;
    
    /**
     *
     * @var HttpUtils
     */
    protected $httpUtils;
    
    /**
     *
     * @var LoggerInterface
     */
    protected $logger;
    
    /**
     *
     * @var EventDispatcherInterface
     */
    protected $dispatcher;
    
    /**
     * If true, will redirect to the login form
     *
     * @var boolean
     */
    protected $redirectToFormLogin = false;

    public function __construct(SecurityContextInterface $securityContext,
            AuthenticationManagerInterface $authenticationManager, HttpUtils $httpUtils,
            LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null,
            $redirectToFormLogin = true)
    {

        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->httpUtils = $httpUtils;
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
        $this->redirectToFormLogin = $redirectToFormLogin;
    }

    /**
     * Authenticates the Wordpress cookie in the request. Depending upon $redirectToFormLogin, 
     * either silently returns or redirects to Wordpress login on failure.
     *
     * @param GetResponseEvent $event
     * @return null
     */
    public function handle(GetResponseEvent $event) 
    {
        # Don't try to authenticate again if the user already has been
        if ($this->securityContext->getToken()) {
            return;
        }
        
        try {
            // Authentication manager uses a list of AuthenticationProviderInterface instances 
            // to authenticate a Token.
            $token = $this->authenticationManager->authenticate(new NtlmProtocolToken());
            $this->securityContext->setToken($token);
            
            # Notify listeners that the user has been logged in
            if ($this->dispatcher) {
                $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN,
                    new InteractiveLoginEvent($event->getRequest(), $token));
            }
            
            if ($this->logger) {
                $this->logger->debug(sprintf(
                    'NTLM user "%s" authenticated', $token->getUsername()));
            }
            
        } catch (AuthenticationException $e) {
        }
    }
}
