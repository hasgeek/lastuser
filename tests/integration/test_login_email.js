var system = require('system'),
    test_username = system.env.TEST_USERNAME,
    test_password = system.env.TEST_PASSWORD,
    host = "http://localhost:7500";

casper.test.begin('Lastuser redirects to correct Lastuser login page', 1, function (test){
    casper.start(host, function() {
        this.echo("Check for running server");
        test.assertHttpStatus(200, '200 OK');
        casper.clear();
        phantom.clearCookies();
        casper.thenOpenAndEvaluate(host+"/login", function(test_username, test_password){
            document.querySelector('#username').value = test_username;
            document.querySelector('#password').value = test_password;
            document.querySelector('#passwordlogin').submit();
        }, test_username, test_password);
        casper.waitForUrl(host, function(){
            casper.thenOpen(host+"/apps", function(){
                casper.echo("Logged in, indeed!");
                casper.echo("Cookies:" + JSON.stringify(phantom.cookies));
            });
        });
    });

    casper.run(function(){
        test.done();
    });
});
