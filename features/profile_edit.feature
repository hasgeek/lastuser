Feature: Open user profile page
  Scenario: login an existing user and open profile page
    Given we have an existing user
    and the user is logged in
    when the user visits their profile page
    then the user can see their details
    and the user can edit their profile
    and the user can change their password
