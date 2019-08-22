Feature: Failed user registration
  Scenario: register a new user with a used username
    Given a new user trying to register with a used username
    when this new user submits the registration form with a username that has already been used
    then the new user will not be registered
