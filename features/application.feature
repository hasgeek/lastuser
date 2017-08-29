Feature: Add a client application
  Scenario: login an existing user and add a client application
    Given we have an existing user
    and the user is logged in
    when the user visits the client application page
    then the user can add a new client application
    and the user can edit the new client application
    and the user can add a new organization
    and the user profile page lists new application and organization
