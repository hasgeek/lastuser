var system = require('system');
var host = "http://localhost:7500";

casper.test.begin('Lastuser redirects to correct Google login page', 3, function (test){
    casper.start(host, function() {
        this.echo("Check for running server");
        test.assertHttpStatus(200, '200 OK');
    });

    login_url = host+"/login/google";
    casper.thenOpen(login_url, function() {
        this.echo("Hit login endpoint");
        test.assertHttpStatus(200, "200 OK");
        this.echo("Check if redirected URL leads to Google");
        test.assertUrlMatch(/accounts.google.com\/o\/oauth2\/v2\/auth/, 'Redirected to Google login successfully');
    });

    casper.run(function(){
        test.done();
    });
});
