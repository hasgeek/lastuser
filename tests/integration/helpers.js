var system = require('system'),
    test_username = system.env.TEST_USERNAME,
    test_password = system.env.TEST_PASSWORD;

module.exports = {
    login: function(casper, host) {
        casper.clear();
        phantom.clearCookies();
        casper.thenOpenAndEvaluate(host+"/login", function(username, password){
            document.querySelector('#username').value = username;
            document.querySelector('#password').value = password;
            document.querySelector('#passwordlogin').submit();
        }, test_username, test_password);
        casper.waitForUrl(host, function(){
            casper.thenOpen(host+"/apps", function(){
                casper.echo("Logged in, indeed!");
                casper.echo("Cookies:" + JSON.stringify(phantom.cookies));
            });
        });
    },

    logout: function(casper, host) {
        casper.thenOpenAndEvaluate(host, function(){
            var profileOptions = document.querySelectorAll('ul .dropdown-menu a');
            for (var i = 0; i< profileOptions.length; i++){
                if (profileOptions[i].innerText == "Logout"){
                    profileOptions[i].click();
                }
            }
        });
        casper.waitForUrl(host, function(){
            casper.thenOpen(host+"/apps", function(){
                casper.test.assertUrlMatch(host+"/login", this.getCurrentUrl(), "Logged out, indeed!");
            });
        });
    }
};
