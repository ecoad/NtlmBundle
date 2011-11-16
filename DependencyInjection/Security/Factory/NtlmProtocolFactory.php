<?php
namespace BrowserCreative\NtlmBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;

class NtlmProtocolFactory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'ntlm.security.authentication.provider.ntlmprotocol.' . $id;
        $container->setDefinition($providerId,
            new DefinitionDecorator('ntlm.security.authentication.provider.ntlmprotocol'));

        $listenerId = 'ntlm.security.authentication.listener.ntlmprotocol.' . $id;
        $container->setDefinition($listenerId,
            new DefinitionDecorator('ntlm.security.authentication.listener.ntlmprotocol'))
            ->addArgument($config['redirect_to_login_form_on_failure']);

        # If the application does logouts, add our handler to log the user out of Wordpress, too
        if ($container->hasDefinition('security.logout_listener.'.$id)) {
            $logoutListener = $container->getDefinition('security.logout_listener.'.$id);
            $addHandlerArguments = array(new Reference('ntlm.security.http.logout.' . $id));
            
            # Don't add the handler again if it has already been added by another factory
            if (!in_array(array('addHandler', $addHandlerArguments),
                    $logoutListener->getMethodCalls())) {
                
                $container->setDefinition('ntlm.security.http.logout.' . $id,
                            new DefinitionDecorator('ntlm.security.http.logout'));
                $logoutListener->addMethodCall('addHandler', $addHandlerArguments);
            }
        }

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    public function getPosition()
    {
        return 'remember_me';
    }

    public function getKey()
    {
        return 'ntlm-protocol';
    }

    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->booleanNode('redirect_to_login_form_on_failure')->defaultValue(true)->end()
            ->end()
        ;
    }
}