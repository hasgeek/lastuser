Feature: Succesful user registration
  Scenario: register a new user
    Given we have a new user
    when a new user submits the registration form with the proper details
    then the new user will be registered
