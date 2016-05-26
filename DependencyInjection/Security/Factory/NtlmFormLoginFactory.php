<?php
namespace BrowserCreative\NtlmBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\FormLoginFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;

class NtlmFormLoginFactory extends FormLoginFactory
{
    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $providerId = 'ntlm.security.authentication.provider.login.' . $id;
        $container->setDefinition($providerId,
            new DefinitionDecorator('ntlm.security.authentication.provider.login'))
            ->replaceArgument(0, $config['remember_me_parameter'])
            ->replaceArgument(2, new Reference($userProviderId));

        # If the application does logout, add our handler to log the user out of connected apps, too
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

        return $providerId;
    }
    
    protected function isRememberMeAware($config)
    {   
        return false;
    }

    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        
        $node
            ->children()
                ->scalarNode('remember_me_parameter')
                    ->defaultValue('_remember_me')->cannotBeEmpty()
                ->end()
            ->end()
        ;
    }

    public function getKey()
    {
        return 'ntlm-form-login';
    }
}