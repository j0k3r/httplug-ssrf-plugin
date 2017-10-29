<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__)
;

return PhpCsFixer\Config::create()
    ->setRules([
        'concat_space' => true,
    ])
    ->setFinder($finder)
;
