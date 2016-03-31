var system = require('system');
var host = "http://localhost:7500";

casper.test.begin('Lastuser redirects to correct Github login page', 3, function (test){
    casper.start(host, function() {
        this.echo("Check for running server");
        test.assertHttpStatus(200, '200 OK');
    });

    // Hit login endpoint
    login_url = host+"/login/github";
    casper.thenOpen(login_url, function() {
        this.echo("Hit login endpoint");
        test.assertHttpStatus(200, "200 OK");
        this.echo("Check if redirected URL leads to Github");
        test.assertUrlMatch(/github.com\/login\?/, 'Redirected to Github login successfully');
    });

    casper.run(function(){
        test.done();
    });
});
