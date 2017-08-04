Feature: User Login
  Scenario: existing user logs in
    Given we have an existing user
    When the user tries to log in
    Then we log the user in
