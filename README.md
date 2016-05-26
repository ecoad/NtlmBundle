This bundle is in development

Description
===========
This bundle sets up the NTLM authentication provider for your application. If there is NTLM data 
provided by the browser, then the application will try and authenticate the provided username against 
your user provider/chain user providers

Requirements
============

* Symfony 2.0.x

Installation
============

1. Register the namespace `BrowserCreative` to your project's autoloader bootstrap script:

        // app/autoload.php

        $loader->registerNamespaces(array(
              // ...
              'BrowserCreative'    => __DIR__.'/../vendor/bundles',
              // ...
        ));

2. Add this bundle to your application's kernel:

        // app/AppKernel.php

        public function registerBundles()
        {
            return array(
                // ...
                new BrowserCreative\NtlmBundle\BrowserCreativeNtlmBundle(),
                // ...
            );
        }


3. Update your security.yml:

        security:
            factories:
                - "%kernel.root_dir%/../vendor/bundles/BrowserCreative/NtlmBundle/Resources/config/security_factories.xml"

            providers:
                ...

            firewalls:
                secured_area:
                    pattern: ^/
                    ntlm_protocol:
                        provider: chain_provider
                        redirect_to_login_form_on_failure: true
                        ntlm_addresses: [ ...list of ip addresses authorized to do NTLM auth... ]
                    ntlm_form_login:
                        provider: chain_provider
                        remember_me_parameter: _remember_me
                    logout: ~
                    anonymous: true
            
            ...

4. Optional: set the following 2 parameters:

        parameters:
            browser_detection.mobile: 'regexp...'
            browser_detection.desktop 'regexp...'

When set, they will be matched against the user-agent string from the browser:
- any mobile browser will not use NTLM auth (i.e. a blacklist)
- only desktop browsers will use NTLM auth (i.e. a whitelist; not setting it means 'all except the mobile ones')

Notes
=====
* The two authentication providers (NtlmProtocolAuthenticationProvider, NtlmFormLoginAuthenticationProvider) pass 
tokens to the user provider instead of the username. Feel free to change this back, it's just that our User Providers 
require the tokens because they rely on the password to access the database (LDAP)


