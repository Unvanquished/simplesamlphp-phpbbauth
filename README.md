# simplesamlphp-phpbbauth
Allows you to login using phpbb3 credentials. It loads the bare minimum of phpbb3 to start the authenticiation process.

## Setup
Inside the simplesamlphp module directory, run:
```git clone https://github.com/Unvanquished/simplesamlphp-phpbbauth.git phpbbauth```
Then, in config/authsources.php, add
```
    'phpbb3' => array(
    'phpbbauth:Auth',
    'phpbb_root' => 'PATH TO PHPBB3 ROOT',
),
```
