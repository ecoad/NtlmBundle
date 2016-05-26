<?php
namespace BrowserCreative\NtlmBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use BrowserCreative\NtlmBundle\DependencyInjection\Security\Factory\NtlmProtocolFactory;
use BrowserCreative\NtlmBundle\DependencyInjection\Security\Factory\NtlmFormLoginFactory;

class BrowserCreativeNtlmBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        // register the factories which set up the custom auth providers
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new NtlmProtocolFactory());
        $extension->addSecurityListenerFactory(new NtlmFormLoginFactory());
    }
}
