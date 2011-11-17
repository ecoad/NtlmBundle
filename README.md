Requirements
============

* Symfony 2.0.x

Usage 
=====

(TODO)

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
(TODO)


