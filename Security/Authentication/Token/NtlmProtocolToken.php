<?php
namespace BrowserCreative\NtlmBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use BrowserCreative\NtlmBundle\Security\User\User;

class NtlmProtocolToken extends AbstractToken
{

    public function __construct(User $user = null) {
        if ($user instanceof User) {
            parent::__construct($user->getRoles());
            $this->setUser($user);
            parent::setAuthenticated(true);
            
        } else {
            parent::__construct();
        }
    }

    public function setAuthenticated($isAuthenticated)
    {
        if ($isAuthenticated) {
            throw new \LogicException(
                    'Cannot set this token to trusted after instantiation.');
        }

        parent::setAuthenticated(false);
    }

    public function getCredentials()
    {
        return '';
    }
}