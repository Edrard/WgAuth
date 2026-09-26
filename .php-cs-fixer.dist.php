<?php
declare(strict_types=1);
$finder = PhpCsFixer\Finder::create()->in(__DIR__.'/src')->in(__DIR__.'/tests')->in(__DIR__.'/examples');
return (new PhpCsFixer\Config())->setRules(['@PSR12' => true])->setFinder($finder);