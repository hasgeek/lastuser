var helpers = require('./helpers.js'),
    system = require('system'),
    host = "http://localhost:7500";

casper.test.begin('Lastuser redirects to correct Lastuser login page', 1, function (test){
    casper.start(host, function() {
        this.echo("Check for running server");
        test.assertHttpStatus(200, '200 OK');
        helpers.login(casper, host);
    });

    casper.run(function(){
        test.done();
    });
});
