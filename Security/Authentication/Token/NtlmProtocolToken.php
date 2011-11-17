<?php
namespace BrowserCreative\NtlmBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

class NtlmProtocolToken extends AbstractToken
{

    public function __construct(UserInterface $user = null) {
        if ($user) {
            parent::__construct($user->getRoles());
            $this->setUser($user);
            parent::setAuthenticated(true);
        }
    }

    public function __tostring() {
        if ($this->getUser()) {
            return (string)$this->getUser()->getUsername();
        }

        return '';
    }

    public function getCredentials() {
        return $this->getUser()->getCredentials();
    }

    public function setAuthenticated($isAuthenticated)
    {
        if ($isAuthenticated) {
            throw new \LogicException(
                    'Cannot set this token to trusted after instantiation.');
        }

        parent::setAuthenticated(false);
    }
}