# MultiCORS
Apache custom module to built-in handle multiple CORS domains (aka "Access-Control-Allow-Origin").
Just install it and forget to code an *ad-hoc* solution!


## How it works
* Compile the module using `apxs -i -a -c multiCORS.c`
* Create a `file` that contains allowed domains (onea each line, max 128)
* Modify your `config` file (usually under `/etc/apache2/apache2.conf`
  * Add `Access-Control-Allow-Multi-Origin "file"`
* Restart Apache (`service apache2 restart`)

IMPORTANT NOTE: This handler runs **before** `mod_rewrite`, so it's necessary that you have it loaded.
You can just put a dummy operation to `mod_rewrite` on your `.htaccess` file, like:

    RewriteEngine On
    RewriteCond "$1.html" -f
    RewriteCond "$1.htm" !-f
    RewriteRule "^(.\*).htm$ "$1.html"
    
So your `.htm` pages will work as `html`


It will drop a log file under `/var/log/apache2/multiCORS.log`

Once all steps are done, every domain listed on `file` will be allowed to get resources from your server.


## Anything else?
Have any doubt? Issue? Problem? Drop an email to doscar.sole@gmail.com, or do a pull request!
