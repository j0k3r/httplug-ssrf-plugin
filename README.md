# Server-Side Request Forgery (SSRF) protection plugin for HTTPlug

[![Build Status](https://travis-ci.org/j0k3r/httplug-ssrf-plugin.svg?branch=master)](https://travis-ci.org/j0k3r/httplug-ssrf-plugin)
[![Code Coverage](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/j0k3r/httplug-ssrf-plugin/?branch=master)

Inspired from [SafeCurl](https://github.com/j0k3r/safecurl), it intends to validate each part of the URL against a white or black list, to help protect against _Server-Side Request Forgery_ attacks when using HTTPlug.

Each part of the URL is broken down and validated against a white or black list. This includes resolve a domain name to it's IP addresses.

## Installation

It can be included in any PHP project using [Composer](https://getcomposer.org). Include the following in your `composer.json` file under `require`.

```
"require": {
    "j0k3r\httplug-ssrf-plugin": "dev-master"
}
```

Then update Composer.

```
composer update
```

## Usage

TBA
