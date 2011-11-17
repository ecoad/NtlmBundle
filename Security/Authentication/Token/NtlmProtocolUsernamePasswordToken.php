<?php

namespace BrowserCreative\NtlmBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class NtlmProtocolUsernamePasswordToken extends UsernamePasswordToken {
    public function __toString() {
        if ($this->getUser()) {
            return $this->getUser()->getUsername();
        }

        return parent::__toString();
    }
}