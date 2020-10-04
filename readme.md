# N26 Php Laravel Wrapper

## Installation

	composer require rene-roscher/number26

## Usage

```php

$n26 = new \RServices\Number26('your@emailAddress.com', 'password');

// Get Transactions
$transactions = $n26->getTransactions();

// Get Me
$me = $n26->getMe();

// Get Contacts
$contacts = $n26->getContacts();